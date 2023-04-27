# SubscriptionCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**SubscriptionCreateRequestDataAttributes**](SubscriptionCreateRequestDataAttributes.md) |  | 
**Relationships** | [**SubscriptionCreateRequestDataRelationships**](SubscriptionCreateRequestDataRelationships.md) |  | 

## Methods

### NewSubscriptionCreateRequestData

`func NewSubscriptionCreateRequestData(type_ string, attributes SubscriptionCreateRequestDataAttributes, relationships SubscriptionCreateRequestDataRelationships, ) *SubscriptionCreateRequestData`

NewSubscriptionCreateRequestData instantiates a new SubscriptionCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionCreateRequestDataWithDefaults

`func NewSubscriptionCreateRequestDataWithDefaults() *SubscriptionCreateRequestData`

NewSubscriptionCreateRequestDataWithDefaults instantiates a new SubscriptionCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *SubscriptionCreateRequestData) GetAttributes() SubscriptionCreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionCreateRequestData) GetAttributesOk() (*SubscriptionCreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionCreateRequestData) SetAttributes(v SubscriptionCreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *SubscriptionCreateRequestData) GetRelationships() SubscriptionCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionCreateRequestData) GetRelationshipsOk() (*SubscriptionCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionCreateRequestData) SetRelationships(v SubscriptionCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


