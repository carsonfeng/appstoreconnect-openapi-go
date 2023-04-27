# SubscriptionAvailability

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppAvailabilityAttributes**](AppAvailabilityAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionAvailabilityRelationships**](SubscriptionAvailabilityRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionAvailability

`func NewSubscriptionAvailability(type_ string, id string, links ResourceLinks, ) *SubscriptionAvailability`

NewSubscriptionAvailability instantiates a new SubscriptionAvailability object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionAvailabilityWithDefaults

`func NewSubscriptionAvailabilityWithDefaults() *SubscriptionAvailability`

NewSubscriptionAvailabilityWithDefaults instantiates a new SubscriptionAvailability object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionAvailability) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionAvailability) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionAvailability) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionAvailability) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionAvailability) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionAvailability) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionAvailability) GetAttributes() AppAvailabilityAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionAvailability) GetAttributesOk() (*AppAvailabilityAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionAvailability) SetAttributes(v AppAvailabilityAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionAvailability) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionAvailability) GetRelationships() SubscriptionAvailabilityRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionAvailability) GetRelationshipsOk() (*SubscriptionAvailabilityRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionAvailability) SetRelationships(v SubscriptionAvailabilityRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionAvailability) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionAvailability) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionAvailability) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionAvailability) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


