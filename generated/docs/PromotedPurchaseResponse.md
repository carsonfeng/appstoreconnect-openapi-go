# PromotedPurchaseResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**PromotedPurchase**](PromotedPurchase.md) |  | 
**Included** | Pointer to [**[]PromotedPurchasesResponseIncludedInner**](PromotedPurchasesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewPromotedPurchaseResponse

`func NewPromotedPurchaseResponse(data PromotedPurchase, links DocumentLinks, ) *PromotedPurchaseResponse`

NewPromotedPurchaseResponse instantiates a new PromotedPurchaseResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPromotedPurchaseResponseWithDefaults

`func NewPromotedPurchaseResponseWithDefaults() *PromotedPurchaseResponse`

NewPromotedPurchaseResponseWithDefaults instantiates a new PromotedPurchaseResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *PromotedPurchaseResponse) GetData() PromotedPurchase`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *PromotedPurchaseResponse) GetDataOk() (*PromotedPurchase, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *PromotedPurchaseResponse) SetData(v PromotedPurchase)`

SetData sets Data field to given value.


### GetIncluded

`func (o *PromotedPurchaseResponse) GetIncluded() []PromotedPurchasesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *PromotedPurchaseResponse) GetIncludedOk() (*[]PromotedPurchasesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *PromotedPurchaseResponse) SetIncluded(v []PromotedPurchasesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *PromotedPurchaseResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *PromotedPurchaseResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *PromotedPurchaseResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *PromotedPurchaseResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


