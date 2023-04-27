# CiIssue

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiIssueAttributes**](CiIssueAttributes.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiIssue

`func NewCiIssue(type_ string, id string, links ResourceLinks, ) *CiIssue`

NewCiIssue instantiates a new CiIssue object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiIssueWithDefaults

`func NewCiIssueWithDefaults() *CiIssue`

NewCiIssueWithDefaults instantiates a new CiIssue object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiIssue) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiIssue) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiIssue) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiIssue) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiIssue) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiIssue) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiIssue) GetAttributes() CiIssueAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiIssue) GetAttributesOk() (*CiIssueAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiIssue) SetAttributes(v CiIssueAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiIssue) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetLinks

`func (o *CiIssue) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiIssue) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiIssue) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


