// Copyright 2019 OVO Technology
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

package location

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	awsSsm "github.com/aws/aws-sdk-go/service/ssm"
	"github.com/ovotech/cloud-key-rotator/pkg/cred"
)

// Ssm type
type Ssm struct {
	KeyParamName   string
	KeyIDParamName string
	Region         string
	ConvertToFile  bool
	FileType       string
}

func (ssm Ssm) Write(serviceAccountName string, keyWrapper KeyWrapper, creds cred.Credentials) (updated UpdatedLocation, err error) {
	provider := keyWrapper.KeyProvider
	var key string
	var keyEnvVar string
	var keyIDEnvVar string
	var idValue bool

	if keyEnvVar, err = getVarNameFromProvider(provider, ssm.KeyParamName, idValue); err != nil {
		return
	}

	if ssm.ConvertToFile || provider == "gcp" {
		if key, err = getKeyForFileBasedLocation(keyWrapper, ssm.FileType); err != nil {
			return
		}
	} else {
		key = keyWrapper.Key
		idValue = true
		if keyIDEnvVar, err = getVarNameFromProvider(provider, ssm.KeyIDParamName, idValue); err != nil {
			return
		}
	}

	svc := awsSsm.New(session.New())
	svc.Config.Region = aws.String(ssm.Region)

	if len(keyIDEnvVar) > 0 {
		if err = updateSSMParameter(keyIDEnvVar, keyWrapper.KeyID, "String", *svc); err != nil {
			return
		}
	}
	if err = updateSSMParameter(keyEnvVar, key, "SecureString", *svc); err != nil {
		return
	}

	updated = UpdatedLocation{
		LocationType: "SSM",
		LocationURI:  ssm.Region,
		LocationIDs:  []string{keyIDEnvVar, keyEnvVar}}
	return
}

func updateSSMParameter(paramName, paramValue, paramType string, svc awsSsm.SSM) (err error) {
	input := &awsSsm.PutParameterInput{
		Overwrite: aws.Bool(true),
		Name:      aws.String(paramName),
		Value:     aws.String(paramValue),
		Type:      aws.String(paramType),
	}
	_, err = svc.PutParameter(input)
	return
}
