# SubscriptionUpdateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionUpdateRequestDataAttributes**](SubscriptionUpdateRequestDataAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionUpdateRequestDataRelationships**](SubscriptionUpdateRequestDataRelationships.md) |  | [optional] 

## Methods

### NewSubscriptionUpdateRequestData

`func NewSubscriptionUpdateRequestData(type_ string, id string, ) *SubscriptionUpdateRequestData`

NewSubscriptionUpdateRequestData instantiates a new SubscriptionUpdateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionUpdateRequestDataWithDefaults

`func NewSubscriptionUpdateRequestDataWithDefaults() *SubscriptionUpdateRequestData`

NewSubscriptionUpdateRequestDataWithDefaults instantiates a new SubscriptionUpdateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionUpdateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionUpdateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionUpdateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionUpdateRequestData) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionUpdateRequestData) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionUpdateRequestData) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionUpdateRequestData) GetAttributes() SubscriptionUpdateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionUpdateRequestData) GetAttributesOk() (*SubscriptionUpdateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionUpdateRequestData) SetAttributes(v SubscriptionUpdateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionUpdateRequestData) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionUpdateRequestData) GetRelationships() SubscriptionUpdateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionUpdateRequestData) GetRelationshipsOk() (*SubscriptionUpdateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionUpdateRequestData) SetRelationships(v SubscriptionUpdateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionUpdateRequestData) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


