# AppEventCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**AppEventCreateRequestDataAttributes**](AppEventCreateRequestDataAttributes.md) |  | 
**Relationships** | [**AppEventCreateRequestDataRelationships**](AppEventCreateRequestDataRelationships.md) |  | 

## Methods

### NewAppEventCreateRequestData

`func NewAppEventCreateRequestData(type_ string, attributes AppEventCreateRequestDataAttributes, relationships AppEventCreateRequestDataRelationships, ) *AppEventCreateRequestData`

NewAppEventCreateRequestData instantiates a new AppEventCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventCreateRequestDataWithDefaults

`func NewAppEventCreateRequestDataWithDefaults() *AppEventCreateRequestData`

NewAppEventCreateRequestDataWithDefaults instantiates a new AppEventCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppEventCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppEventCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppEventCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *AppEventCreateRequestData) GetAttributes() AppEventCreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppEventCreateRequestData) GetAttributesOk() (*AppEventCreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppEventCreateRequestData) SetAttributes(v AppEventCreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *AppEventCreateRequestData) GetRelationships() AppEventCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppEventCreateRequestData) GetRelationshipsOk() (*AppEventCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppEventCreateRequestData) SetRelationships(v AppEventCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


