package msp

import (
	"container/heap"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// A UserDatabase is an abstraction over the name -> share map returned by the
// secret splitter that allows an application to only decrypt or request shares
// when needed, rather than re-build a partial map of known data.
type UserDatabase interface {
	ValidUser(name string) bool
	CanGetShare(string) bool
	GetShare(string) ([][]byte, error)
}

type Condition interface { // Represents one condition in a predicate
	Ok(*UserDatabase) bool
}

type String struct { // Type of condition
	string
	index int
}

func (s String) Ok(db *UserDatabase) bool {
	return (*db).CanGetShare(s.string)
}

type TraceElem struct {
	loc   int
	names []string
	trace []string
}

type TraceSlice []TraceElem

func (ts TraceSlice) Len() int      { return len(ts) }
func (ts TraceSlice) Swap(i, j int) { ts[i], ts[j] = ts[j], ts[i] }

func (ts TraceSlice) Less(i, j int) bool {
	return len(ts[i].trace) < len(ts[j].trace)
}

func (ts *TraceSlice) Push(te interface{}) { *ts = append(*ts, te.(TraceElem)) }
func (ts *TraceSlice) Pop() interface{} {
	out := (*ts)[0]
	*ts = (*ts)[1 : len(*ts)-1]

	return out
}

func (ts TraceSlice) Compact() (index []int, names []string, trace []string) {
	for _, te := range ts {
		index = append(index, te.loc)
		names = append(names, te.names...)
		trace = append(trace, te.trace...)
	}

	ptr, cutoff := 0, len(trace)

TopLoop:
	for ptr < cutoff {
		for i := 0; i < ptr; i++ {
			if trace[i] == trace[ptr] {
				trace[ptr], trace[cutoff-1] = trace[cutoff-1], trace[ptr]
				cutoff--

				continue TopLoop
			}
		}

		ptr++
	}
	trace = trace[0:cutoff]

	return
}

type MSP Formatted

func Modulus(n int) (modulus *big.Int) {
	switch n {
	case 256:
		modulus = big.NewInt(1) // 2^256 - 2^224 + 2^192 + 2^96 - 1
		modulus.Lsh(modulus, 256)
		modulus.Sub(modulus, big.NewInt(0).Lsh(big.NewInt(1), 224))
		modulus.Add(modulus, big.NewInt(0).Lsh(big.NewInt(1), 192))
		modulus.Add(modulus, big.NewInt(0).Lsh(big.NewInt(1), 96))
		modulus.Sub(modulus, big.NewInt(1))

	case 224:
		modulus = big.NewInt(1) // 2^224 - 2^96 + 1
		modulus.Lsh(modulus, 224)
		modulus.Sub(modulus, big.NewInt(0).Lsh(big.NewInt(1), 96))
		modulus.Add(modulus, big.NewInt(1))

	default: // Silent fail.
		modulus = big.NewInt(1) // 2^127 - 1
		modulus.Lsh(modulus, 127)
		modulus.Sub(modulus, big.NewInt(1))
	}

	return
}

func StringToMSP(pred string) (m MSP, err error) {
	var f Formatted

	if -1 == strings.Index(pred, ",") {
		var r Raw
		r, err = StringToRaw(pred)
		if err != nil {
			return
		}

		f = r.Formatted()
	} else {
		f, err = StringToFormatted(pred)
		if err != nil {
			return
		}
	}

	return MSP(f), nil
}

func (m MSP) DerivePath(db *UserDatabase) (ok bool, names []string, locs []int, trace []string) {
	ts := &TraceSlice{}

	for i, cond := range m.Conds {
		switch cond.(type) {
		case String:
			if (*db).CanGetShare(cond.(String).string) {
				heap.Push(ts, TraceElem{
					i,
					[]string{cond.(String).string},
					[]string{cond.(String).string},
				})
			}

		case Formatted:
			sok, _, _, strace := MSP(cond.(Formatted)).DerivePath(db)
			if !sok {
				continue
			}

			heap.Push(ts, TraceElem{i, []string{}, strace})
		}

		if (*ts).Len() > m.Min {
			*ts = (*ts)[0:m.Min]
		}
	}

	ok = (*ts).Len() >= m.Min
	locs, names, trace = ts.Compact()
	return
}

func (m MSP) DistributeShares(sec []byte, modulus *big.Int, db *UserDatabase) (map[string][][]byte, error) {
	out := make(map[string][][]byte)

	// Math to distribute shares.
	secInt := big.NewInt(0).SetBytes(sec) // Convert secret to number.
	secInt.Mod(secInt, modulus)

	var junk []*big.Int // Generate junk numbers.
	for i := 1; i < m.Min; i++ {
		r := make([]byte, (modulus.BitLen()/8)+1)
		_, err := rand.Read(r)
		if err != nil {
			return out, err
		}

		s := big.NewInt(0).SetBytes(r)
		s.Mod(s, modulus)

		junk = append(junk, s)
	}

	for i, cond := range m.Conds { // Calculate shares.
		share := big.NewInt(1)
		share.Mul(share, secInt)

		for j := 2; j <= m.Min; j++ {
			cell := big.NewInt(int64(i + 1))
			cell.Exp(cell, big.NewInt(int64(j-1)), modulus)
			// CELL SHOULD ALWAYS BE LESS THAN MODULUS

			share.Add(share, cell.Mul(cell, junk[j-2])).Mod(share, modulus)
		}

		switch cond.(type) {
		case String:
			name := cond.(String).string
			if _, ok := out[name]; ok {
				out[name] = append(out[name], share.Bytes())
			} else if (*db).ValidUser(name) {
				out[name] = [][]byte{share.Bytes()}
			} else {
				return out, errors.New("Unknown user in predicate.")
			}

		default:
			below := MSP(cond.(Formatted))
			subOut, err := below.DistributeShares(share.Bytes(), modulus, db)
			if err != nil {
				return out, err
			}

			for name, shares := range subOut {
				if _, ok := out[name]; ok {
					out[name] = append(out[name], shares...)
				} else {
					out[name] = shares
				}

			}
		}
	}

	return out, nil
}

func (m MSP) RecoverSecret(modulus *big.Int, db *UserDatabase) ([]byte, error) {
	cache := make(map[string][][]byte, 0) // Caches un-used shares for a user.
	return m.recoverSecret(modulus, db, cache)
}

func (m MSP) recoverSecret(modulus *big.Int, db *UserDatabase, cache map[string][][]byte) ([]byte, error) {
	var (
		index  = []int{}    // Indexes where given shares were in the matrix.
		shares = [][]byte{} // Contains shares that will be used in reconstruction.
	)

	ok, names, locs, _ := m.DerivePath(db)
	if !ok {
		return nil, errors.New("Not enough shares to recover.")
	}

	for _, name := range names {
		if _, cached := cache[name]; !cached {
			out, err := (*db).GetShare(name)
			if err != nil {
				return nil, err
			}

			cache[name] = out
		}
	}

	for _, loc := range locs {
		gate := m.Conds[loc]
		index = append(index, loc+1)

		switch gate.(type) {
		case String:
			if len(cache[gate.(String).string]) <= gate.(String).index {
				return nil, errors.New("Predicate / database mismatch!")
			}

			shares = append(shares, cache[gate.(String).string][gate.(String).index])

		case Formatted:
			share, err := MSP(gate.(Formatted)).recoverSecret(modulus, db, cache)
			if err != nil {
				return nil, err
			}

			shares = append(shares, share)
		}
	}

	// Calculate the reconstruction vector.  We only need the top row of the
	// matrix's inverse, so we augment M transposed with u1 transposed and
	// eliminate Gauss-Jordan style.
	matrix := [][][2]int{}              // 2d grid of (numerator, denominator)
	matrix = append(matrix, [][2]int{}) // Create first row of all 1s

	for j := 0; j < m.Min; j++ {
		matrix[0] = append(matrix[0], [2]int{1, 1})
	}

	for j := 1; j < m.Min; j++ { // Fill in rest of matrix.
		row := [][2]int{}

		for k, idx := range index {
			row = append(row, [2]int{int(idx) * matrix[j-1][k][0], matrix[j-1][k][1]})
		}

		matrix = append(matrix, row)
	}

	matrix[0] = append(matrix[0], [2]int{1, 1}) // Stick on last column.
	for j := 1; j < m.Min; j++ {
		matrix[j] = append(matrix[j], [2]int{0, 1})
	}

	// Reduce matrix.
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ { // Make row unary.
			if i == j {
				continue
			}

			matrix[i][j][0] *= matrix[i][i][1]
			matrix[i][j][1] *= matrix[i][i][0]
		}
		matrix[i][i] = [2]int{1, 1}

		for j := 0; j < len(matrix); j++ { // Remove this row from the others.
			if i == j {
				continue
			}

			top := matrix[j][i][0]
			bot := matrix[j][i][1]

			for k := 0; k < len(matrix[j]); k++ {
				// matrix[j][k] = matrix[j][k] - matrix[j][i] * matrix[i][k]
				temp := [2]int{0, 0}
				temp[0] = top * matrix[i][k][0]
				temp[1] = bot * matrix[i][k][1]

				if matrix[j][k][0] == 0 {
					matrix[j][k][0] = -temp[0]
					matrix[j][k][1] = temp[1]
				} else {
					matrix[j][k][0] = (matrix[j][k][0] * temp[1]) - (temp[0] * matrix[j][k][1])
					matrix[j][k][1] *= temp[1]
				}

				if matrix[j][k][0] == 0 {
					matrix[j][k][1] = 1
				}
			}
		}
	}

	// Compute dot product of the shares vector and the reconstruction vector to
	// reconstruct the secret.
	size := len(modulus.Bytes())
	out := make([]byte, size)
	secInt := big.NewInt(0)

	for i, share := range shares {
		lst := len(matrix[i]) - 1

		num := big.NewInt(int64(matrix[i][lst][0]))
		den := big.NewInt(int64(matrix[i][lst][1]))
		num.Mod(num, modulus)
		den.Mod(den, modulus)

		coeff := big.NewInt(0).ModInverse(den, modulus)
		coeff.Mul(coeff, num).Mod(coeff, modulus)

		shareInt := big.NewInt(0).SetBytes(share)
		shareInt.Mul(shareInt, coeff).Mod(shareInt, modulus)

		secInt.Add(secInt, shareInt).Mod(secInt, modulus)
	}

	out = append(out, secInt.Bytes()...)
	return out[len(out)-size:], nil
}
