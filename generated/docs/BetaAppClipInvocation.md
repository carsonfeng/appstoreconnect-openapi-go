# BetaAppClipInvocation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**BetaAppClipInvocationAttributes**](BetaAppClipInvocationAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**BetaAppClipInvocationRelationships**](BetaAppClipInvocationRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewBetaAppClipInvocation

`func NewBetaAppClipInvocation(type_ string, id string, links ResourceLinks, ) *BetaAppClipInvocation`

NewBetaAppClipInvocation instantiates a new BetaAppClipInvocation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBetaAppClipInvocationWithDefaults

`func NewBetaAppClipInvocationWithDefaults() *BetaAppClipInvocation`

NewBetaAppClipInvocationWithDefaults instantiates a new BetaAppClipInvocation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *BetaAppClipInvocation) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *BetaAppClipInvocation) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *BetaAppClipInvocation) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *BetaAppClipInvocation) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *BetaAppClipInvocation) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *BetaAppClipInvocation) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *BetaAppClipInvocation) GetAttributes() BetaAppClipInvocationAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *BetaAppClipInvocation) GetAttributesOk() (*BetaAppClipInvocationAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *BetaAppClipInvocation) SetAttributes(v BetaAppClipInvocationAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *BetaAppClipInvocation) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *BetaAppClipInvocation) GetRelationships() BetaAppClipInvocationRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *BetaAppClipInvocation) GetRelationshipsOk() (*BetaAppClipInvocationRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *BetaAppClipInvocation) SetRelationships(v BetaAppClipInvocationRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *BetaAppClipInvocation) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *BetaAppClipInvocation) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *BetaAppClipInvocation) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *BetaAppClipInvocation) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


