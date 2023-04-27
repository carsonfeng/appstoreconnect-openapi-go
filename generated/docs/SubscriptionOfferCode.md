# SubscriptionOfferCode

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionOfferCodeAttributes**](SubscriptionOfferCodeAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionOfferCodeRelationships**](SubscriptionOfferCodeRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionOfferCode

`func NewSubscriptionOfferCode(type_ string, id string, links ResourceLinks, ) *SubscriptionOfferCode`

NewSubscriptionOfferCode instantiates a new SubscriptionOfferCode object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeWithDefaults

`func NewSubscriptionOfferCodeWithDefaults() *SubscriptionOfferCode`

NewSubscriptionOfferCodeWithDefaults instantiates a new SubscriptionOfferCode object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionOfferCode) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionOfferCode) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionOfferCode) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionOfferCode) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionOfferCode) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionOfferCode) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionOfferCode) GetAttributes() SubscriptionOfferCodeAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionOfferCode) GetAttributesOk() (*SubscriptionOfferCodeAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionOfferCode) SetAttributes(v SubscriptionOfferCodeAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionOfferCode) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionOfferCode) GetRelationships() SubscriptionOfferCodeRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionOfferCode) GetRelationshipsOk() (*SubscriptionOfferCodeRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionOfferCode) SetRelationships(v SubscriptionOfferCodeRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionOfferCode) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCode) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCode) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCode) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


