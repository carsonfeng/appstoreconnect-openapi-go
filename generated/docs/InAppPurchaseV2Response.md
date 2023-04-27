# InAppPurchaseV2Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchaseV2**](InAppPurchaseV2.md) |  | 
**Included** | Pointer to [**[]InAppPurchasesV2ResponseIncludedInner**](InAppPurchasesV2ResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewInAppPurchaseV2Response

`func NewInAppPurchaseV2Response(data InAppPurchaseV2, links DocumentLinks, ) *InAppPurchaseV2Response`

NewInAppPurchaseV2Response instantiates a new InAppPurchaseV2Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseV2ResponseWithDefaults

`func NewInAppPurchaseV2ResponseWithDefaults() *InAppPurchaseV2Response`

NewInAppPurchaseV2ResponseWithDefaults instantiates a new InAppPurchaseV2Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchaseV2Response) GetData() InAppPurchaseV2`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchaseV2Response) GetDataOk() (*InAppPurchaseV2, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchaseV2Response) SetData(v InAppPurchaseV2)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchaseV2Response) GetIncluded() []InAppPurchasesV2ResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchaseV2Response) GetIncludedOk() (*[]InAppPurchasesV2ResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchaseV2Response) SetIncluded(v []InAppPurchasesV2ResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchaseV2Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseV2Response) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseV2Response) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseV2Response) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


