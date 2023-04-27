/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
)

// checks if the ScmPullRequestAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ScmPullRequestAttributes{}

// ScmPullRequestAttributes struct for ScmPullRequestAttributes
type ScmPullRequestAttributes struct {
	Title                      *string `json:"title,omitempty"`
	Number                     *int32  `json:"number,omitempty"`
	WebUrl                     *string `json:"webUrl,omitempty"`
	SourceRepositoryOwner      *string `json:"sourceRepositoryOwner,omitempty"`
	SourceRepositoryName       *string `json:"sourceRepositoryName,omitempty"`
	SourceBranchName           *string `json:"sourceBranchName,omitempty"`
	DestinationRepositoryOwner *string `json:"destinationRepositoryOwner,omitempty"`
	DestinationRepositoryName  *string `json:"destinationRepositoryName,omitempty"`
	DestinationBranchName      *string `json:"destinationBranchName,omitempty"`
	IsClosed                   *bool   `json:"isClosed,omitempty"`
	IsCrossRepository          *bool   `json:"isCrossRepository,omitempty"`
}

// NewScmPullRequestAttributes instantiates a new ScmPullRequestAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewScmPullRequestAttributes() *ScmPullRequestAttributes {
	this := ScmPullRequestAttributes{}
	return &this
}

// NewScmPullRequestAttributesWithDefaults instantiates a new ScmPullRequestAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewScmPullRequestAttributesWithDefaults() *ScmPullRequestAttributes {
	this := ScmPullRequestAttributes{}
	return &this
}

// GetTitle returns the Title field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetTitle() string {
	if o == nil || IsNil(o.Title) {
		var ret string
		return ret
	}
	return *o.Title
}

// GetTitleOk returns a tuple with the Title field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetTitleOk() (*string, bool) {
	if o == nil || IsNil(o.Title) {
		return nil, false
	}
	return o.Title, true
}

// HasTitle returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasTitle() bool {
	if o != nil && !IsNil(o.Title) {
		return true
	}

	return false
}

// SetTitle gets a reference to the given string and assigns it to the Title field.
func (o *ScmPullRequestAttributes) SetTitle(v string) {
	o.Title = &v
}

// GetNumber returns the Number field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetNumber() int32 {
	if o == nil || IsNil(o.Number) {
		var ret int32
		return ret
	}
	return *o.Number
}

// GetNumberOk returns a tuple with the Number field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetNumberOk() (*int32, bool) {
	if o == nil || IsNil(o.Number) {
		return nil, false
	}
	return o.Number, true
}

// HasNumber returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasNumber() bool {
	if o != nil && !IsNil(o.Number) {
		return true
	}

	return false
}

// SetNumber gets a reference to the given int32 and assigns it to the Number field.
func (o *ScmPullRequestAttributes) SetNumber(v int32) {
	o.Number = &v
}

// GetWebUrl returns the WebUrl field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetWebUrl() string {
	if o == nil || IsNil(o.WebUrl) {
		var ret string
		return ret
	}
	return *o.WebUrl
}

// GetWebUrlOk returns a tuple with the WebUrl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetWebUrlOk() (*string, bool) {
	if o == nil || IsNil(o.WebUrl) {
		return nil, false
	}
	return o.WebUrl, true
}

// HasWebUrl returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasWebUrl() bool {
	if o != nil && !IsNil(o.WebUrl) {
		return true
	}

	return false
}

// SetWebUrl gets a reference to the given string and assigns it to the WebUrl field.
func (o *ScmPullRequestAttributes) SetWebUrl(v string) {
	o.WebUrl = &v
}

// GetSourceRepositoryOwner returns the SourceRepositoryOwner field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetSourceRepositoryOwner() string {
	if o == nil || IsNil(o.SourceRepositoryOwner) {
		var ret string
		return ret
	}
	return *o.SourceRepositoryOwner
}

// GetSourceRepositoryOwnerOk returns a tuple with the SourceRepositoryOwner field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetSourceRepositoryOwnerOk() (*string, bool) {
	if o == nil || IsNil(o.SourceRepositoryOwner) {
		return nil, false
	}
	return o.SourceRepositoryOwner, true
}

// HasSourceRepositoryOwner returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasSourceRepositoryOwner() bool {
	if o != nil && !IsNil(o.SourceRepositoryOwner) {
		return true
	}

	return false
}

// SetSourceRepositoryOwner gets a reference to the given string and assigns it to the SourceRepositoryOwner field.
func (o *ScmPullRequestAttributes) SetSourceRepositoryOwner(v string) {
	o.SourceRepositoryOwner = &v
}

// GetSourceRepositoryName returns the SourceRepositoryName field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetSourceRepositoryName() string {
	if o == nil || IsNil(o.SourceRepositoryName) {
		var ret string
		return ret
	}
	return *o.SourceRepositoryName
}

// GetSourceRepositoryNameOk returns a tuple with the SourceRepositoryName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetSourceRepositoryNameOk() (*string, bool) {
	if o == nil || IsNil(o.SourceRepositoryName) {
		return nil, false
	}
	return o.SourceRepositoryName, true
}

// HasSourceRepositoryName returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasSourceRepositoryName() bool {
	if o != nil && !IsNil(o.SourceRepositoryName) {
		return true
	}

	return false
}

// SetSourceRepositoryName gets a reference to the given string and assigns it to the SourceRepositoryName field.
func (o *ScmPullRequestAttributes) SetSourceRepositoryName(v string) {
	o.SourceRepositoryName = &v
}

// GetSourceBranchName returns the SourceBranchName field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetSourceBranchName() string {
	if o == nil || IsNil(o.SourceBranchName) {
		var ret string
		return ret
	}
	return *o.SourceBranchName
}

// GetSourceBranchNameOk returns a tuple with the SourceBranchName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetSourceBranchNameOk() (*string, bool) {
	if o == nil || IsNil(o.SourceBranchName) {
		return nil, false
	}
	return o.SourceBranchName, true
}

// HasSourceBranchName returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasSourceBranchName() bool {
	if o != nil && !IsNil(o.SourceBranchName) {
		return true
	}

	return false
}

// SetSourceBranchName gets a reference to the given string and assigns it to the SourceBranchName field.
func (o *ScmPullRequestAttributes) SetSourceBranchName(v string) {
	o.SourceBranchName = &v
}

// GetDestinationRepositoryOwner returns the DestinationRepositoryOwner field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetDestinationRepositoryOwner() string {
	if o == nil || IsNil(o.DestinationRepositoryOwner) {
		var ret string
		return ret
	}
	return *o.DestinationRepositoryOwner
}

// GetDestinationRepositoryOwnerOk returns a tuple with the DestinationRepositoryOwner field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetDestinationRepositoryOwnerOk() (*string, bool) {
	if o == nil || IsNil(o.DestinationRepositoryOwner) {
		return nil, false
	}
	return o.DestinationRepositoryOwner, true
}

// HasDestinationRepositoryOwner returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasDestinationRepositoryOwner() bool {
	if o != nil && !IsNil(o.DestinationRepositoryOwner) {
		return true
	}

	return false
}

// SetDestinationRepositoryOwner gets a reference to the given string and assigns it to the DestinationRepositoryOwner field.
func (o *ScmPullRequestAttributes) SetDestinationRepositoryOwner(v string) {
	o.DestinationRepositoryOwner = &v
}

// GetDestinationRepositoryName returns the DestinationRepositoryName field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetDestinationRepositoryName() string {
	if o == nil || IsNil(o.DestinationRepositoryName) {
		var ret string
		return ret
	}
	return *o.DestinationRepositoryName
}

// GetDestinationRepositoryNameOk returns a tuple with the DestinationRepositoryName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetDestinationRepositoryNameOk() (*string, bool) {
	if o == nil || IsNil(o.DestinationRepositoryName) {
		return nil, false
	}
	return o.DestinationRepositoryName, true
}

// HasDestinationRepositoryName returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasDestinationRepositoryName() bool {
	if o != nil && !IsNil(o.DestinationRepositoryName) {
		return true
	}

	return false
}

// SetDestinationRepositoryName gets a reference to the given string and assigns it to the DestinationRepositoryName field.
func (o *ScmPullRequestAttributes) SetDestinationRepositoryName(v string) {
	o.DestinationRepositoryName = &v
}

// GetDestinationBranchName returns the DestinationBranchName field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetDestinationBranchName() string {
	if o == nil || IsNil(o.DestinationBranchName) {
		var ret string
		return ret
	}
	return *o.DestinationBranchName
}

// GetDestinationBranchNameOk returns a tuple with the DestinationBranchName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetDestinationBranchNameOk() (*string, bool) {
	if o == nil || IsNil(o.DestinationBranchName) {
		return nil, false
	}
	return o.DestinationBranchName, true
}

// HasDestinationBranchName returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasDestinationBranchName() bool {
	if o != nil && !IsNil(o.DestinationBranchName) {
		return true
	}

	return false
}

// SetDestinationBranchName gets a reference to the given string and assigns it to the DestinationBranchName field.
func (o *ScmPullRequestAttributes) SetDestinationBranchName(v string) {
	o.DestinationBranchName = &v
}

// GetIsClosed returns the IsClosed field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetIsClosed() bool {
	if o == nil || IsNil(o.IsClosed) {
		var ret bool
		return ret
	}
	return *o.IsClosed
}

// GetIsClosedOk returns a tuple with the IsClosed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetIsClosedOk() (*bool, bool) {
	if o == nil || IsNil(o.IsClosed) {
		return nil, false
	}
	return o.IsClosed, true
}

// HasIsClosed returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasIsClosed() bool {
	if o != nil && !IsNil(o.IsClosed) {
		return true
	}

	return false
}

// SetIsClosed gets a reference to the given bool and assigns it to the IsClosed field.
func (o *ScmPullRequestAttributes) SetIsClosed(v bool) {
	o.IsClosed = &v
}

// GetIsCrossRepository returns the IsCrossRepository field value if set, zero value otherwise.
func (o *ScmPullRequestAttributes) GetIsCrossRepository() bool {
	if o == nil || IsNil(o.IsCrossRepository) {
		var ret bool
		return ret
	}
	return *o.IsCrossRepository
}

// GetIsCrossRepositoryOk returns a tuple with the IsCrossRepository field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ScmPullRequestAttributes) GetIsCrossRepositoryOk() (*bool, bool) {
	if o == nil || IsNil(o.IsCrossRepository) {
		return nil, false
	}
	return o.IsCrossRepository, true
}

// HasIsCrossRepository returns a boolean if a field has been set.
func (o *ScmPullRequestAttributes) HasIsCrossRepository() bool {
	if o != nil && !IsNil(o.IsCrossRepository) {
		return true
	}

	return false
}

// SetIsCrossRepository gets a reference to the given bool and assigns it to the IsCrossRepository field.
func (o *ScmPullRequestAttributes) SetIsCrossRepository(v bool) {
	o.IsCrossRepository = &v
}

func (o ScmPullRequestAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ScmPullRequestAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Title) {
		toSerialize["title"] = o.Title
	}
	if !IsNil(o.Number) {
		toSerialize["number"] = o.Number
	}
	if !IsNil(o.WebUrl) {
		toSerialize["webUrl"] = o.WebUrl
	}
	if !IsNil(o.SourceRepositoryOwner) {
		toSerialize["sourceRepositoryOwner"] = o.SourceRepositoryOwner
	}
	if !IsNil(o.SourceRepositoryName) {
		toSerialize["sourceRepositoryName"] = o.SourceRepositoryName
	}
	if !IsNil(o.SourceBranchName) {
		toSerialize["sourceBranchName"] = o.SourceBranchName
	}
	if !IsNil(o.DestinationRepositoryOwner) {
		toSerialize["destinationRepositoryOwner"] = o.DestinationRepositoryOwner
	}
	if !IsNil(o.DestinationRepositoryName) {
		toSerialize["destinationRepositoryName"] = o.DestinationRepositoryName
	}
	if !IsNil(o.DestinationBranchName) {
		toSerialize["destinationBranchName"] = o.DestinationBranchName
	}
	if !IsNil(o.IsClosed) {
		toSerialize["isClosed"] = o.IsClosed
	}
	if !IsNil(o.IsCrossRepository) {
		toSerialize["isCrossRepository"] = o.IsCrossRepository
	}
	return toSerialize, nil
}

type NullableScmPullRequestAttributes struct {
	value *ScmPullRequestAttributes
	isSet bool
}

func (v NullableScmPullRequestAttributes) Get() *ScmPullRequestAttributes {
	return v.value
}

func (v *NullableScmPullRequestAttributes) Set(val *ScmPullRequestAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableScmPullRequestAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableScmPullRequestAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableScmPullRequestAttributes(val *ScmPullRequestAttributes) *NullableScmPullRequestAttributes {
	return &NullableScmPullRequestAttributes{value: val, isSet: true}
}

func (v NullableScmPullRequestAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableScmPullRequestAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
