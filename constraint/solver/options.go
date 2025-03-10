package solver

import (
	"fmt"

	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
)

// Option defines option for altering the behavior of a constraint system
// solver (Solve() method). See the descriptions of functions returning instances
// of this type for implemented options.
type Option func(*Config) error

// Config is the configuration for the solver with the options applied.
type Config struct {
	HintFunctions map[HintID]HintFn // defaults to all built-in hint functions
	Logger        zerolog.Logger    // defaults to gnark.Logger
}

// WithHints is a solver option that specifies additional hint functions to be used
// by the constraint solver.
func WithHints(hintFunctions ...Hint) Option {
	log := logger.Logger()
	return func(opt *Config) error {
		// it is an error to register hint function several times, but as the
		// prover already checks it then omit here.
		for _, h := range hintFunctions {
			uuid := h.ID
			if _, ok := opt.HintFunctions[uuid]; ok {
				log.Warn().Int("hintID", int(uuid)).Str("id", fmt.Sprintf("%d", h.ID)).Msg("duplicate hint function")
			} else {
				opt.HintFunctions[uuid] = h.Fn
			}
		}
		return nil
	}
}

// OverrideHint forces the solver to use provided hint function for given id.
func OverrideHint(id HintID, f HintFn) Option {
	return func(opt *Config) error {
		opt.HintFunctions[id] = f
		return nil
	}
}

// WithLogger is a prover option that specifies zerolog.Logger as a destination for the
// logs printed by api.Println(). By default, uses gnark/logger.
// zerolog.Nop() will disable logging
func WithLogger(l zerolog.Logger) Option {
	return func(opt *Config) error {
		opt.Logger = l
		return nil
	}
}

// NewConfig returns a default SolverConfig with given prover options opts applied.
func NewConfig(opts ...Option) (Config, error) {
	log := logger.Logger()
	opt := Config{Logger: log, HintFunctions: make(map[HintID]HintFn)}
	for k, v := range GetRegisteredHints() {
		opt.HintFunctions[k] = v // copy
	}
	for _, option := range opts {
		if err := option(&opt); err != nil {
			return Config{}, err
		}
	}
	return opt, nil
}
