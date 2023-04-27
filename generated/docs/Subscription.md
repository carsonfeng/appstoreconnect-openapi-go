# Subscription

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionAttributes**](SubscriptionAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionRelationships**](SubscriptionRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscription

`func NewSubscription(type_ string, id string, links ResourceLinks, ) *Subscription`

NewSubscription instantiates a new Subscription object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionWithDefaults

`func NewSubscriptionWithDefaults() *Subscription`

NewSubscriptionWithDefaults instantiates a new Subscription object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *Subscription) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *Subscription) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *Subscription) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *Subscription) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *Subscription) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *Subscription) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *Subscription) GetAttributes() SubscriptionAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *Subscription) GetAttributesOk() (*SubscriptionAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *Subscription) SetAttributes(v SubscriptionAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *Subscription) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *Subscription) GetRelationships() SubscriptionRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *Subscription) GetRelationshipsOk() (*SubscriptionRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *Subscription) SetRelationships(v SubscriptionRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *Subscription) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *Subscription) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *Subscription) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *Subscription) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


