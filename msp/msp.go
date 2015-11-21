package msp

import (
	"container/heap"
	"crypto/rand"
	"errors"
	"strings"
)

// A UserDatabase is an abstraction over the name -> share map returned by the
// secret splitter that allows an application to only decrypt or request shares
// when needed, rather than re-build a partial map of known data.
type UserDatabase interface {
	ValidUser(name string) bool
	CanGetShare(name string) bool
	GetShare(name string) ([][]byte, error)
}

type Condition interface { // Represents one condition in a predicate
	Ok(*UserDatabase) bool
}

type Name struct { // Type of condition
	string
	index int
}

func (n Name) Ok(db *UserDatabase) bool {
	return (*db).CanGetShare(n.string)
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
		case Name:
			if (*db).CanGetShare(cond.(Name).string) {
				heap.Push(ts, TraceElem{
					i,
					[]string{cond.(Name).string},
					[]string{cond.(Name).string},
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

// DistributeShares takes as input a secret and a user database and returns secret shares according to access structure
// described by the MSP.
func (m MSP) DistributeShares(sec []byte, db *UserDatabase) (map[string][][]byte, error) {
	out := make(map[string][][]byte)

	// Generate a Vandermonde matrix.
	height, width := len(m.Conds), m.Min
	M := Matrix(make([]Row, height))

	for i := 0; i < height; i++ {
		M[i] = NewRow(width)

		for j := 0; j < width; j++ {
			M[i][j][0] = byte(i + 1)
			M[i][j] = M[i][j].Exp(j)
		}
	}

	// Convert secret vector.
	s := NewRow(width)
	s[0] = FieldElem(sec)

	for i := 1; i < width; i++ {
		r := NewFieldElem()
		rand.Read(r)

		s[i] = FieldElem(r)
	}

	// Calculate shares.
	shares := M.Mul(s)

	// Distribute the shares.
	for i, cond := range m.Conds {
		share := shares[i]

		switch cond.(type) {
		case Name:
			name := cond.(Name).string
			if _, ok := out[name]; ok {
				out[name] = append(out[name], share)
			} else if (*db).ValidUser(name) {
				out[name] = [][]byte{share}
			} else {
				return out, errors.New("Unknown user in predicate.")
			}

		default:
			below := MSP(cond.(Formatted))
			subOut, err := below.DistributeShares(share, db)
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

// RecoverSecret takes a user database storing secret shares as input and returns the original secret.
func (m MSP) RecoverSecret(db *UserDatabase) ([]byte, error) {
	cache := make(map[string][][]byte, 0) // Caches un-used shares for a user.
	return m.recoverSecret(db, cache)
}

func (m MSP) recoverSecret(db *UserDatabase, cache map[string][][]byte) ([]byte, error) {
	var (
		index  = []int{}       // Indexes where given shares were in the matrix.
		shares = []FieldElem{} // Contains shares that will be used in reconstruction.
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
		case Name:
			if len(cache[gate.(Name).string]) <= gate.(Name).index {
				return nil, errors.New("Predicate / database mismatch!")
			}

			shares = append(shares, FieldElem(cache[gate.(Name).string][gate.(Name).index]))

		case Formatted:
			share, err := MSP(gate.(Formatted)).recoverSecret(db, cache)
			if err != nil {
				return nil, err
			}

			shares = append(shares, FieldElem(share))
		}
	}

	// Generate the Vandermonde matrix specific to whichever users' shares we're using.
	MSub := Matrix(make([]Row, m.Min))

	for i := 0; i < m.Min; i++ {
		MSub[i] = NewRow(m.Min)

		for j := 0; j < m.Min; j++ {
			MSub[i][j][0] = byte(index[i])
			MSub[i][j] = MSub[i][j].Exp(j)
		}
	}

	// Calculate the reconstruction vector and use it to recover the secret.
	r, ok := MSub.Recovery()
	if !ok {
		return nil, errors.New("Unable to find a reconstruction vector!")
	}

	// Compute dot product of the shares vector and the reconstruction vector to
	// recover the secret.
	s := Row(shares).DotProduct(r)

	return []byte(s), nil
}
