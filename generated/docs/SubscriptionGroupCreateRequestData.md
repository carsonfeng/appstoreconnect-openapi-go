# SubscriptionGroupCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**SubscriptionGroupCreateRequestDataAttributes**](SubscriptionGroupCreateRequestDataAttributes.md) |  | 
**Relationships** | [**AppEventCreateRequestDataRelationships**](AppEventCreateRequestDataRelationships.md) |  | 

## Methods

### NewSubscriptionGroupCreateRequestData

`func NewSubscriptionGroupCreateRequestData(type_ string, attributes SubscriptionGroupCreateRequestDataAttributes, relationships AppEventCreateRequestDataRelationships, ) *SubscriptionGroupCreateRequestData`

NewSubscriptionGroupCreateRequestData instantiates a new SubscriptionGroupCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupCreateRequestDataWithDefaults

`func NewSubscriptionGroupCreateRequestDataWithDefaults() *SubscriptionGroupCreateRequestData`

NewSubscriptionGroupCreateRequestDataWithDefaults instantiates a new SubscriptionGroupCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionGroupCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionGroupCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionGroupCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *SubscriptionGroupCreateRequestData) GetAttributes() SubscriptionGroupCreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionGroupCreateRequestData) GetAttributesOk() (*SubscriptionGroupCreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionGroupCreateRequestData) SetAttributes(v SubscriptionGroupCreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *SubscriptionGroupCreateRequestData) GetRelationships() AppEventCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionGroupCreateRequestData) GetRelationshipsOk() (*AppEventCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionGroupCreateRequestData) SetRelationships(v AppEventCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


