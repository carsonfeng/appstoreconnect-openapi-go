# SubscriptionOfferCodesResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionOfferCodeCustomCodeAttributes**](SubscriptionOfferCodeCustomCodeAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionOfferCodePriceRelationships**](SubscriptionOfferCodePriceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionOfferCodesResponseIncludedInner

`func NewSubscriptionOfferCodesResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *SubscriptionOfferCodesResponseIncludedInner`

NewSubscriptionOfferCodesResponseIncludedInner instantiates a new SubscriptionOfferCodesResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodesResponseIncludedInnerWithDefaults

`func NewSubscriptionOfferCodesResponseIncludedInnerWithDefaults() *SubscriptionOfferCodesResponseIncludedInner`

NewSubscriptionOfferCodesResponseIncludedInnerWithDefaults instantiates a new SubscriptionOfferCodesResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionOfferCodesResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionOfferCodesResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetAttributes() SubscriptionOfferCodeCustomCodeAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetAttributesOk() (*SubscriptionOfferCodeCustomCodeAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionOfferCodesResponseIncludedInner) SetAttributes(v SubscriptionOfferCodeCustomCodeAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionOfferCodesResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetRelationships() SubscriptionOfferCodePriceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetRelationshipsOk() (*SubscriptionOfferCodePriceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionOfferCodesResponseIncludedInner) SetRelationships(v SubscriptionOfferCodePriceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionOfferCodesResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCodesResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCodesResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


