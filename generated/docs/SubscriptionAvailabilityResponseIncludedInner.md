# SubscriptionAvailabilityResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**TerritoryAttributes**](TerritoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionRelationships**](SubscriptionRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionAvailabilityResponseIncludedInner

`func NewSubscriptionAvailabilityResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *SubscriptionAvailabilityResponseIncludedInner`

NewSubscriptionAvailabilityResponseIncludedInner instantiates a new SubscriptionAvailabilityResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionAvailabilityResponseIncludedInnerWithDefaults

`func NewSubscriptionAvailabilityResponseIncludedInnerWithDefaults() *SubscriptionAvailabilityResponseIncludedInner`

NewSubscriptionAvailabilityResponseIncludedInnerWithDefaults instantiates a new SubscriptionAvailabilityResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionAvailabilityResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionAvailabilityResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetAttributes() TerritoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetAttributesOk() (*TerritoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionAvailabilityResponseIncludedInner) SetAttributes(v TerritoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionAvailabilityResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetRelationships() SubscriptionRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetRelationshipsOk() (*SubscriptionRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionAvailabilityResponseIncludedInner) SetRelationships(v SubscriptionRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionAvailabilityResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionAvailabilityResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionAvailabilityResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


