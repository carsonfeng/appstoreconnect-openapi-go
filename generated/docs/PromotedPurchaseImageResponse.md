# PromotedPurchaseImageResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**PromotedPurchaseImage**](PromotedPurchaseImage.md) |  | 
**Included** | Pointer to [**[]PromotedPurchase**](PromotedPurchase.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewPromotedPurchaseImageResponse

`func NewPromotedPurchaseImageResponse(data PromotedPurchaseImage, links DocumentLinks, ) *PromotedPurchaseImageResponse`

NewPromotedPurchaseImageResponse instantiates a new PromotedPurchaseImageResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPromotedPurchaseImageResponseWithDefaults

`func NewPromotedPurchaseImageResponseWithDefaults() *PromotedPurchaseImageResponse`

NewPromotedPurchaseImageResponseWithDefaults instantiates a new PromotedPurchaseImageResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *PromotedPurchaseImageResponse) GetData() PromotedPurchaseImage`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *PromotedPurchaseImageResponse) GetDataOk() (*PromotedPurchaseImage, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *PromotedPurchaseImageResponse) SetData(v PromotedPurchaseImage)`

SetData sets Data field to given value.


### GetIncluded

`func (o *PromotedPurchaseImageResponse) GetIncluded() []PromotedPurchase`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *PromotedPurchaseImageResponse) GetIncludedOk() (*[]PromotedPurchase, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *PromotedPurchaseImageResponse) SetIncluded(v []PromotedPurchase)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *PromotedPurchaseImageResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *PromotedPurchaseImageResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *PromotedPurchaseImageResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *PromotedPurchaseImageResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


