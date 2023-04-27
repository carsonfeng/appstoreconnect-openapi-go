# SubscriptionPricePointResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionPricePoint**](SubscriptionPricePoint.md) |  | 
**Included** | Pointer to [**[]Territory**](Territory.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionPricePointResponse

`func NewSubscriptionPricePointResponse(data SubscriptionPricePoint, links DocumentLinks, ) *SubscriptionPricePointResponse`

NewSubscriptionPricePointResponse instantiates a new SubscriptionPricePointResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPricePointResponseWithDefaults

`func NewSubscriptionPricePointResponseWithDefaults() *SubscriptionPricePointResponse`

NewSubscriptionPricePointResponseWithDefaults instantiates a new SubscriptionPricePointResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPricePointResponse) GetData() SubscriptionPricePoint`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPricePointResponse) GetDataOk() (*SubscriptionPricePoint, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPricePointResponse) SetData(v SubscriptionPricePoint)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPricePointResponse) GetIncluded() []Territory`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPricePointResponse) GetIncludedOk() (*[]Territory, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPricePointResponse) SetIncluded(v []Territory)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPricePointResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPricePointResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPricePointResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPricePointResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


