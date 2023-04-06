// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package plonk implements PLONK Zero Knowledge Proof system.
//
// # See also
//
// https://eprint.iacr.org/2019/953
package plonk

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	plonk_bn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/backend/witness"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"

	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"

	gnarkio "github.com/consensys/gnark/io"
)

// Proof represents a Plonk proof generated by plonk.Prove
//
// it's underlying implementation is curve specific (see gnark/internal/backend)
type Proof interface {
	io.WriterTo
	io.ReaderFrom
	gnarkio.WriterRawTo
}

// ProvingKey represents a plonk ProvingKey
//
// it's underlying implementation is strongly typed with the curve (see gnark/internal/backend)
type ProvingKey interface {
	io.WriterTo
	io.ReaderFrom
	InitKZG(srs kzg.SRS) error
	VerifyingKey() interface{}
}

// VerifyingKey represents a plonk VerifyingKey
//
// it's underlying implementation is strongly typed with the curve (see gnark/internal/backend)
type VerifyingKey interface {
	io.WriterTo
	io.ReaderFrom
	InitKZG(srs kzg.SRS) error
	NbPublicWitness() int // number of elements expected in the public witness
	ExportSolidity(w io.Writer) error
}

// Setup prepares the public data associated to a circuit + public inputs.
func Setup(ccs constraint.ConstraintSystem, kzgSRS kzg.SRS) (ProvingKey, VerifyingKey, error) {

	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		return plonk_bn254.Setup(tccs, kzgSRS.(*kzg_bn254.SRS))
	default:
		panic("unrecognized SparseR1CS curve type")
	}

}

// Prove generates PLONK proof from a circuit, associated preprocessed public data, and the witness
// if the force flag is set:
//
//		will executes all the prover computations, even if the witness is invalid
//	 will produce an invalid proof
//		internally, the solution vector to the SparseR1CS will be filled with random values which may impact benchmarking
func Prove(ccs constraint.ConstraintSystem, pk ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (Proof, error) {

	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		return plonk_bn254.Prove(tccs, pk.(*plonk_bn254.ProvingKey), fullWitness, opts...)
	default:
		panic("unrecognized SparseR1CS curve type")
	}
}

// Verify verifies a PLONK proof, from the proof, preprocessed public data, and public witness.
func Verify(proof Proof, vk VerifyingKey, publicWitness witness.Witness) error {

	switch _proof := proof.(type) {

	case *plonk_bn254.Proof:
		w, ok := publicWitness.Vector().(fr_bn254.Vector)
		if !ok {
			return witness.ErrInvalidWitness
		}
		return plonk_bn254.Verify(_proof, vk.(*plonk_bn254.VerifyingKey), w)

	default:
		panic("unrecognized proof type")
	}
}

// NewCS instantiate a concrete curved-typed SparseR1CS and return a ConstraintSystem interface
// This method exists for (de)serialization purposes
func NewCS(curveID ecc.ID) constraint.ConstraintSystem {
	var r1cs constraint.ConstraintSystem
	switch curveID {
	case ecc.BN254:
		r1cs = &cs_bn254.SparseR1CS{}
	default:
		panic("not implemented")
	}
	return r1cs
}

// NewProvingKey instantiates a curve-typed ProvingKey and returns an interface
// This function exists for serialization purposes
func NewProvingKey(curveID ecc.ID) ProvingKey {
	var pk ProvingKey
	switch curveID {
	case ecc.BN254:
		pk = &plonk_bn254.ProvingKey{}
	default:
		panic("not implemented")
	}

	return pk
}

// NewProof instantiates a curve-typed ProvingKey and returns an interface
// This function exists for serialization purposes
func NewProof(curveID ecc.ID) Proof {
	var proof Proof
	switch curveID {
	case ecc.BN254:
		proof = &plonk_bn254.Proof{}
	default:
		panic("not implemented")
	}

	return proof
}

// NewVerifyingKey instantiates a curve-typed VerifyingKey and returns an interface
// This function exists for serialization purposes
func NewVerifyingKey(curveID ecc.ID) VerifyingKey {
	var vk VerifyingKey
	switch curveID {
	case ecc.BN254:
		vk = &plonk_bn254.VerifyingKey{}
	default:
		panic("not implemented")
	}

	return vk
}
