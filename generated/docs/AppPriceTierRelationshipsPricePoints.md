# AppPriceTierRelationshipsPricePoints

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Links** | Pointer to [**AppAvailabilityRelationshipsAppLinks**](AppAvailabilityRelationshipsAppLinks.md) |  | [optional] 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 
**Data** | Pointer to [**[]AppPriceTierRelationshipsPricePointsDataInner**](AppPriceTierRelationshipsPricePointsDataInner.md) |  | [optional] 

## Methods

### NewAppPriceTierRelationshipsPricePoints

`func NewAppPriceTierRelationshipsPricePoints() *AppPriceTierRelationshipsPricePoints`

NewAppPriceTierRelationshipsPricePoints instantiates a new AppPriceTierRelationshipsPricePoints object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPriceTierRelationshipsPricePointsWithDefaults

`func NewAppPriceTierRelationshipsPricePointsWithDefaults() *AppPriceTierRelationshipsPricePoints`

NewAppPriceTierRelationshipsPricePointsWithDefaults instantiates a new AppPriceTierRelationshipsPricePoints object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLinks

`func (o *AppPriceTierRelationshipsPricePoints) GetLinks() AppAvailabilityRelationshipsAppLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPriceTierRelationshipsPricePoints) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPriceTierRelationshipsPricePoints) SetLinks(v AppAvailabilityRelationshipsAppLinks)`

SetLinks sets Links field to given value.

### HasLinks

`func (o *AppPriceTierRelationshipsPricePoints) HasLinks() bool`

HasLinks returns a boolean if a field has been set.

### GetMeta

`func (o *AppPriceTierRelationshipsPricePoints) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppPriceTierRelationshipsPricePoints) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppPriceTierRelationshipsPricePoints) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppPriceTierRelationshipsPricePoints) HasMeta() bool`

HasMeta returns a boolean if a field has been set.

### GetData

`func (o *AppPriceTierRelationshipsPricePoints) GetData() []AppPriceTierRelationshipsPricePointsDataInner`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPriceTierRelationshipsPricePoints) GetDataOk() (*[]AppPriceTierRelationshipsPricePointsDataInner, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPriceTierRelationshipsPricePoints) SetData(v []AppPriceTierRelationshipsPricePointsDataInner)`

SetData sets Data field to given value.

### HasData

`func (o *AppPriceTierRelationshipsPricePoints) HasData() bool`

HasData returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


