package jwt

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	secretFlag string
	algFlag    string
)

func NewJWTCmd() (cmd *cobra.Command) {
	rootCmd := &cobra.Command{
		Use:        "jwt",
		Short:      "[DEPRECATED] Use jwtop instead",
		Deprecated: "jwt token generation has moved to jwtop; see https://www.cerberauth.com/docs/jwtop/installation/",
	}

	generateCmd := &cobra.Command{
		Use:   "generate [token]",
		Short: "[DEPRECATED] Use jwtop sign instead",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("vulnapi jwt generate is deprecated. Install jwtop (https://www.cerberauth.com/docs/jwtop/installation/) and run:\n\n  jwtop sign %s --alg %s --secret %s\n", args[0], algFlag, secretFlag)
		},
	}

	generateCmd.Flags().StringVarP(&secretFlag, "secret", "", "", "Secret key to sign the token")
	generateCmd.Flags().StringVarP(&algFlag, "alg", "", "", "Algorithm to sign the token")

	rootCmd.AddCommand(generateCmd)

	return rootCmd
}
