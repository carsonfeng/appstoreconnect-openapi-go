# SubscriptionPriceCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionPriceInlineCreateAttributes**](SubscriptionPriceInlineCreateAttributes.md) |  | [optional] 
**Relationships** | [**SubscriptionPriceCreateRequestDataRelationships**](SubscriptionPriceCreateRequestDataRelationships.md) |  | 

## Methods

### NewSubscriptionPriceCreateRequestData

`func NewSubscriptionPriceCreateRequestData(type_ string, relationships SubscriptionPriceCreateRequestDataRelationships, ) *SubscriptionPriceCreateRequestData`

NewSubscriptionPriceCreateRequestData instantiates a new SubscriptionPriceCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPriceCreateRequestDataWithDefaults

`func NewSubscriptionPriceCreateRequestDataWithDefaults() *SubscriptionPriceCreateRequestData`

NewSubscriptionPriceCreateRequestDataWithDefaults instantiates a new SubscriptionPriceCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionPriceCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionPriceCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionPriceCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *SubscriptionPriceCreateRequestData) GetAttributes() SubscriptionPriceInlineCreateAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionPriceCreateRequestData) GetAttributesOk() (*SubscriptionPriceInlineCreateAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionPriceCreateRequestData) SetAttributes(v SubscriptionPriceInlineCreateAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionPriceCreateRequestData) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionPriceCreateRequestData) GetRelationships() SubscriptionPriceCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionPriceCreateRequestData) GetRelationshipsOk() (*SubscriptionPriceCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionPriceCreateRequestData) SetRelationships(v SubscriptionPriceCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


