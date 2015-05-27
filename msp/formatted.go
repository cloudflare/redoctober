package msp

import (
	"container/list"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Formatted struct { // Represents threshold gate (also type of condition)
	Min   int
	Conds []Condition
}

func StringToFormatted(f string) (out Formatted, err error) {
	// Automaton.  Modification of Dijkstra's Two-Stack Algorithm for parsing
	// infix notation.  Running time linear in the size of the predicate?
	//
	// Steps either to the next comma or the next unparenthesis.
	//     (     -> Push new queue onto staging stack
	//     value -> Push onto back of queue at top of staging stack.
	//     )     -> Pop queue off top of staging stack, build threshold gate,
	//              and push gate onto the back of the top queue.
	//
	// Staging stack is empty on initialization and should have exactly 1 built
	// threshold gate at the end of the string.
	if f[0] != '(' || f[len(f)-1] != ')' {
		return out, errors.New("Invalid string--wrong format.")
	}

	getNext := func(f string) (string, string) { // f -> (next, rest)
		f = strings.TrimSpace(f)

		if f[0] == '(' {
			return f[0:1], f[1:]
		}

		nextComma := strings.Index(f, ",")
		if f[0] == ')' {
			if nextComma == -1 {
				return f[0:1], ""
			}
			return f[0:1], f[nextComma+1:]
		} else if nextComma == -1 {
			return f[0 : len(f)-1], f[len(f)-1:]
		}

		nextUnParen := strings.Index(f, ")")
		if nextComma < nextUnParen {
			return strings.TrimSpace(f[0:nextComma]), f[nextComma+1:]
		}

		return strings.TrimSpace(f[0:nextUnParen]), f[nextUnParen:]
	}

	staging := list.New()
	indices := make(map[string]int, 0)

	var nxt string
	for len(f) > 0 {
		nxt, f = getNext(f)

		switch nxt {
		case "(":
			staging.PushFront(list.New())
		case ")":
			top := staging.Remove(staging.Front()).(*list.List)

			var min int
			minStr := top.Front()
			min, err = strconv.Atoi(minStr.Value.(String).string)
			if err != nil {
				return
			}

			built := Formatted{
				Min:   min,
				Conds: []Condition{},
			}

			for cond := minStr.Next(); cond != nil; cond = cond.Next() {
				built.Conds = append(built.Conds, cond.Value.(Condition))
			}

			if staging.Len() == 0 {
				if len(f) == 0 {
					return built, nil
				}
				return built, errors.New("Invalid string--terminated early.")
			}

			staging.Front().Value.(*list.List).PushBack(built)

		default:
			if _, there := indices[nxt]; !there {
				indices[nxt] = 0
			}

			staging.Front().Value.(*list.List).PushBack(String{nxt, indices[nxt]})
			indices[nxt]++
		}
	}

	return out, errors.New("Invalid string--never terminated.")
}

func (f Formatted) String() string {
	out := fmt.Sprintf("(%v", f.Min)

	for _, cond := range f.Conds {
		switch cond.(type) {
		case String:
			out += fmt.Sprintf(", %v", cond.(String).string)
		case Formatted:
			out += fmt.Sprintf(", %v", (cond.(Formatted)).String())
		}
	}

	return out + ")"
}

func (f Formatted) Ok(db *UserDatabase) bool {
	// Goes through the smallest number of conditions possible to check if the
	// threshold gate returns true.  Sometimes requires recursing down to check
	// nested threshold gates.
	rest := f.Min

	for _, cond := range f.Conds {
		if cond.Ok(db) {
			rest--
		}

		if rest == 0 {
			return true
		}
	}

	return false
}

func (f *Formatted) Compress() {
	if f.Min == len(f.Conds) {
		// AND Compression:  (n, ..., (m, ...), ...) = (n + m, ...)
		skip := 0
		for i, cond := range f.Conds {
			if skip > 0 {
				skip--
				continue
			}

			switch cond.(type) {
			case Formatted:
				cond := cond.(Formatted)
				cond.Compress()
				f.Conds[i] = cond

				if cond.Min == len(cond.Conds) {
					f.Min += cond.Min - 1
					f.Conds = append(f.Conds[0:i],
						append(cond.Conds, f.Conds[i+1:]...)...)
					skip = len(cond.Conds) - 1
				}
			}
		}
	} else if f.Min == 1 {
		// OR Compression: (1, ..., (1, ...), ...) = (1, ...)
		skip := 0
		for i, cond := range f.Conds {
			if skip > 0 {
				skip--
				continue
			}

			switch cond.(type) {
			case Formatted:
				cond := cond.(Formatted)
				cond.Compress()
				f.Conds[i] = cond

				if cond.Min == 1 {
					f.Conds = append(f.Conds[0:i],
						append(cond.Conds, f.Conds[i+1:]...)...)
					skip = len(cond.Conds) - 1
				}
			}
		}
	}
}
