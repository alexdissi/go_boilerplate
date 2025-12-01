package errors

import (
	"fmt"
	"runtime"

	"go.uber.org/zap"
)

// Error est une erreur enrichie avec le stack trace
type Error struct {
	err   error
	stack []string
}

// captureStackTrace capture le stack trace
func captureStackTrace() []string {
	var stack []string
	callers := make([]uintptr, 10)
	n := runtime.Callers(3, callers) // Skip 3 frames: captureStackTrace, New, WithStack
	callers = callers[:n]

	frames := runtime.CallersFrames(callers)
	for {
		frame, more := frames.Next()
		if !more {
			break
		}
		stack = append(stack, fmt.Sprintf("%s:%d %s", frame.File, frame.Line, frame.Function))
	}

	return stack
}

// WithStack add a stack trace to an error wiht zap logging
func WithStack(err error) *Error {
	if err == nil {
		return nil
	}

	stackErr := &Error{
		err:   err,
		stack: captureStackTrace(),
	}

	zap.Strings("stack", stackErr.stack)

	return stackErr
}
