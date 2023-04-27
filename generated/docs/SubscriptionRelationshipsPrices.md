# SubscriptionRelationshipsPrices

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Links** | Pointer to [**AppAvailabilityRelationshipsAppLinks**](AppAvailabilityRelationshipsAppLinks.md) |  | [optional] 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 
**Data** | Pointer to [**[]SubscriptionRelationshipsPricesDataInner**](SubscriptionRelationshipsPricesDataInner.md) |  | [optional] 

## Methods

### NewSubscriptionRelationshipsPrices

`func NewSubscriptionRelationshipsPrices() *SubscriptionRelationshipsPrices`

NewSubscriptionRelationshipsPrices instantiates a new SubscriptionRelationshipsPrices object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionRelationshipsPricesWithDefaults

`func NewSubscriptionRelationshipsPricesWithDefaults() *SubscriptionRelationshipsPrices`

NewSubscriptionRelationshipsPricesWithDefaults instantiates a new SubscriptionRelationshipsPrices object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLinks

`func (o *SubscriptionRelationshipsPrices) GetLinks() AppAvailabilityRelationshipsAppLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionRelationshipsPrices) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionRelationshipsPrices) SetLinks(v AppAvailabilityRelationshipsAppLinks)`

SetLinks sets Links field to given value.

### HasLinks

`func (o *SubscriptionRelationshipsPrices) HasLinks() bool`

HasLinks returns a boolean if a field has been set.

### GetMeta

`func (o *SubscriptionRelationshipsPrices) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionRelationshipsPrices) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionRelationshipsPrices) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionRelationshipsPrices) HasMeta() bool`

HasMeta returns a boolean if a field has been set.

### GetData

`func (o *SubscriptionRelationshipsPrices) GetData() []SubscriptionRelationshipsPricesDataInner`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionRelationshipsPrices) GetDataOk() (*[]SubscriptionRelationshipsPricesDataInner, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionRelationshipsPrices) SetData(v []SubscriptionRelationshipsPricesDataInner)`

SetData sets Data field to given value.

### HasData

`func (o *SubscriptionRelationshipsPrices) HasData() bool`

HasData returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


