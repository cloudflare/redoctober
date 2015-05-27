package msp

import (
	"container/list"
	"errors"
	"strings"
)

type NodeType int // Types of node in the binary expression tree.

const (
	NodeAnd NodeType = iota
	NodeOr
)

func (t NodeType) Type() NodeType {
	return t
}

type Raw struct { // Represents one node in the tree.
	NodeType

	Left  *Condition
	Right *Condition
}

func StringToRaw(r string) (out Raw, err error) {
	// Automaton.  Modification of Dijkstra's Two-Stack Algorithm for parsing
	// infix notation.  Reads one long unbroken expression (several operators and
	// operands with no parentheses) at a time and parses it into a binary
	// expression tree (giving AND operators precedence).  Running time linear in
	// the size of the predicate?
	//
	// Steps to the next (un)parenthesis.
	//     (     -> Push new queue onto staging stack
	//     value -> Push onto back of queue at top of staging stack.
	//     )     -> Pop queue off top of staging stack, build BET, and push tree
	//              onto the back of the top queue.
	//
	// To build the binary expression tree, for each type of operation we iterate
	// through the (Condition, operator) lists compacting where that operation
	// occurs into tree nodes.
	//
	// Staging stack is empty on initialization and should have exactly 1 node
	// (the root node) at the end of the string.
	r = "(" + r + ")"

	min := func(a, b, c int) int { // Return smallest non-negative argument.
		if a > b { // Sort {a, b, c}
			a, b = b, a
		}
		if b > c {
			b, c = c, b
		}
		if a > b {
			a, b = b, a
		}

		if a != -1 {
			return a
		} else if b != -1 {
			return b
		} else {
			return c
		}
	}

	getNext := func(r string) (string, string) { // r -> (next, rest)
		r = strings.TrimSpace(r)

		if r[0] == '(' || r[0] == ')' || r[0] == '&' || r[0] == '|' {
			return r[0:1], r[1:]
		}

		nextOper := min(
			strings.Index(r, "&"),
			strings.Index(r, "|"),
			strings.Index(r, ")"),
		)

		if nextOper == -1 {
			return r, ""
		}
		return strings.TrimSpace(r[0:nextOper]), r[nextOper:]
	}

	staging := list.New() // Stack of (Condition list, operator list)
	indices := make(map[string]int, 0)

	var nxt string
	for len(r) > 0 {
		nxt, r = getNext(r)

		switch nxt {
		case "(":
			staging.PushFront([2]*list.List{list.New(), list.New()})
		case ")":
			top := staging.Remove(staging.Front()).([2]*list.List)
			if top[0].Len() != (top[1].Len() + 1) {
				return out, errors.New("Stacks are invalid size.")
			}

			for typ := NodeAnd; typ <= NodeOr; typ++ {
				var step *list.Element
				leftOperand := top[0].Front()

				for oper := top[1].Front(); oper != nil; oper = step {
					step = oper.Next()

					if oper.Value.(NodeType) == typ {
						left := leftOperand.Value.(Condition)
						right := leftOperand.Next().Value.(Condition)

						leftOperand.Next().Value = Raw{
							NodeType: typ,
							Left:     &left,
							Right:    &right,
						}

						leftOperand = leftOperand.Next()

						top[0].Remove(leftOperand.Prev())
						top[1].Remove(oper)
					} else {
						leftOperand = leftOperand.Next()
					}
				}
			}

			if top[0].Len() != 1 || top[1].Len() != 0 {
				return out, errors.New("Invalid expression--couldn't evaluate.")
			}

			if staging.Len() == 0 {
				if len(r) == 0 {
					return top[0].Front().Value.(Raw), nil
				}
				return out, errors.New("Invalid string--terminated early.")
			}
			staging.Front().Value.([2]*list.List)[0].PushBack(top[0].Front().Value)

		case "&":
			staging.Front().Value.([2]*list.List)[1].PushBack(NodeAnd)
		case "|":
			staging.Front().Value.([2]*list.List)[1].PushBack(NodeOr)
		default:
			if _, there := indices[nxt]; !there {
				indices[nxt] = 0
			}

			staging.Front().Value.([2]*list.List)[0].PushBack(String{nxt, indices[nxt]})
			indices[nxt]++
		}
	}

	return out, errors.New("Invalid string--never terminated.")
}

func (r Raw) String() string {
	out := ""

	switch (*r.Left).(type) {
	case String:
		out += (*r.Left).(String).string
	default:
		out += "(" + (*r.Left).(Raw).String() + ")"
	}

	if r.Type() == NodeAnd {
		out += " & "
	} else {
		out += " | "
	}

	switch (*r.Right).(type) {
	case String:
		out += (*r.Right).(String).string
	default:
		out += "(" + (*r.Right).(Raw).String() + ")"
	}

	return out
}

func (r Raw) Formatted() (out Formatted) {
	// Recursively maps a raw predicate to a formatted predicate by mapping AND
	// gates to (2, A, B) treshold gates and OR gates to (1, A, B) gates.
	if r.Type() == NodeAnd {
		out.Min = 2
	} else {
		out.Min = 1
	}

	switch (*r.Left).(type) {
	case String:
		out.Conds = []Condition{(*r.Left).(String)}
	default:
		out.Conds = []Condition{(*r.Left).(Raw).Formatted()}
	}

	switch (*r.Right).(type) {
	case String:
		out.Conds = append(out.Conds, (*r.Right).(String))
	default:
		out.Conds = append(out.Conds, (*r.Right).(Raw).Formatted())
	}

	out.Compress() // Small amount of predicate compression.
	return
}

func (r Raw) Ok(db *UserDatabase) bool {
	if r.Type() == NodeAnd {
		return (*r.Left).Ok(db) && (*r.Right).Ok(db)
	} else {
		return (*r.Left).Ok(db) || (*r.Right).Ok(db)
	}
}
