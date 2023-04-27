# SubscriptionPricePointsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionPricePoint**](SubscriptionPricePoint.md) |  | 
**Included** | Pointer to [**[]Territory**](Territory.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionPricePointsResponse

`func NewSubscriptionPricePointsResponse(data []SubscriptionPricePoint, links PagedDocumentLinks, ) *SubscriptionPricePointsResponse`

NewSubscriptionPricePointsResponse instantiates a new SubscriptionPricePointsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPricePointsResponseWithDefaults

`func NewSubscriptionPricePointsResponseWithDefaults() *SubscriptionPricePointsResponse`

NewSubscriptionPricePointsResponseWithDefaults instantiates a new SubscriptionPricePointsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPricePointsResponse) GetData() []SubscriptionPricePoint`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPricePointsResponse) GetDataOk() (*[]SubscriptionPricePoint, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPricePointsResponse) SetData(v []SubscriptionPricePoint)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPricePointsResponse) GetIncluded() []Territory`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPricePointsResponse) GetIncludedOk() (*[]Territory, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPricePointsResponse) SetIncluded(v []Territory)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPricePointsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPricePointsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPricePointsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPricePointsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionPricePointsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionPricePointsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionPricePointsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionPricePointsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


