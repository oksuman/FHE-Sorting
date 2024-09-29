package main

import (
	"fmt"
	// "math"
    "github.com/tuneinsight/lattigo/v6/circuits/ckks/minimax"
)

func main() {
    // Calculate logalpha and logerr
    epsilon := 0.01 / 255
    // logalpha := int(math.Ceil(-math.Log2(epsilon)))
    logalpha := 16
    // logerr := logalpha + 1 // Usually, logerr should be <= logalpha
    logerr := 18 // Usually, logerr should be <= logalpha

    // Set precision (adjust as needed)
    // prec := uint(256)
    prec := uint(1000)

    // Set degrees for each polynomial in the composite
    // Adjust these values based on your needs
    // degrees := []int{3, 3, 5, 5, 5, 5, 5, 5, 9}
    degrees := []int{7, 7, 7, 13, 13, 27}

    fmt.Printf("Generating minimax composite polynomial for sign function\n")
    fmt.Printf("Epsilon: %v\n", epsilon)
    fmt.Printf("Log(alpha): %d\n", logalpha)
    fmt.Printf("Log(err): %d\n", logerr)
    fmt.Printf("Precision: %d\n", prec)
    fmt.Printf("Degrees: %v\n\n", degrees)

    minimax.GenMinimaxCompositePolynomialForSign(prec, logalpha, logerr, degrees)
}
