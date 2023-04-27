# InAppPurchaseResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchase**](InAppPurchase.md) |  | 
**Included** | Pointer to [**[]App**](App.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewInAppPurchaseResponse

`func NewInAppPurchaseResponse(data InAppPurchase, links DocumentLinks, ) *InAppPurchaseResponse`

NewInAppPurchaseResponse instantiates a new InAppPurchaseResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseResponseWithDefaults

`func NewInAppPurchaseResponseWithDefaults() *InAppPurchaseResponse`

NewInAppPurchaseResponseWithDefaults instantiates a new InAppPurchaseResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchaseResponse) GetData() InAppPurchase`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchaseResponse) GetDataOk() (*InAppPurchase, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchaseResponse) SetData(v InAppPurchase)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchaseResponse) GetIncluded() []App`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchaseResponse) GetIncludedOk() (*[]App, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchaseResponse) SetIncluded(v []App)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchaseResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


