[![Build Status](https://travis-ci.org/Morras/firebaseJwtValidator.svg?branch=master)](https://travis-ci.org/Morras/firebaseJwtValidator)
[![codecov](https://codecov.io/gh/Morras/firebaseJwtValidator/branch/master/graph/badge.svg)](https://codecov.io/gh/Morras/firebaseJwtValidator)

# firebaseJwtValidator

This is a GO package for validating JWT based identity tokens for Googles Firebase authentication.  
There are many general purpose JWT validators out there that could be used, but this package is a very specific JWT validator for a Firebase project.  

The package validates a token as to the rules described by the Firebase documentation as they where on July 2th 2017 ([Firebase JWT doc](https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library)), specifically it makes the following checks.

### JWT Header
* **alg** = RS256
* **kid** exists

### JWT Claims
* **exp** = now or in the future
* **iat** = now or in the past. Allows for IAT to be up to ten seconds in the future to avoid problems that arose when the validating server was not completely in sync with the JWT issuing server.
* **aud** = a supplied firebase project id
* **iss** = `https://securetoken.google.com/<projectId>` where `<projectID>` is the same value as used in **aud**
* **sub** exists

### JWT Signature
Fetches the public key from Googles key server and validates the JWT signature against the header and claims. 
The package will cache the response from Googles server in accordance with the response `cache-control` `max-age` setting.

Both header and claims sections can have more attributes than the ones listed and they will not be taken into account in the validation.

## Usuage

While it is possible to subtitues your own validators for the header, claims or signature parts of the JWT by implementing one of the `*Validator` interfaces,
the package also supplies default implementations that performs the above rules. Below is a small example of validating a token.

```go
package main

import (
  "fmt"
  fjv "github.com/Morras/firebaseJwtValidator"
  "os"
)

func main() {
  // Use the first command line argument as the token to validate
  token := os.Args[1]
  // Creates the validator with your project ID
  validator := fjv.NewDefaultTokenValidator("Your-Project-ID")
  // Validates a token against the Firebase JWT rules.
  valid, err := validator.Validate(token)

  fmt.Printf("Token is valid: %v\n", valid)
  fmt.Printf("Validation gave the error: %v\n", err)
}
```

## Testing

I have set up a functional test in a cron job on Travis-ci that logs in a user in a test project I have set up only for this project. 
This allows the test to get a fresh token and try an validate that.  
Other than that all classes are unit tested in more or less of a test first fashion.

Testing is done with the [Ginkgo](https://onsi.github.io/ginkgo/) testing framework using [Gomega](https://onsi.github.io/gomega/) matchers, 
but outside those two packages, everything is made using GOs standard library.

## Feedback

I would appreciate any feedback you might have on this code, or just a ping if you are using it. 
I have only messed around with GO on my own, so I am probably still using a Java style where there would be more idomatic ways of doing things in GO.
