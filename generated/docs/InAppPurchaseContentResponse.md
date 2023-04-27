# InAppPurchaseContentResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchaseContent**](InAppPurchaseContent.md) |  | 
**Included** | Pointer to [**[]InAppPurchaseV2**](InAppPurchaseV2.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewInAppPurchaseContentResponse

`func NewInAppPurchaseContentResponse(data InAppPurchaseContent, links DocumentLinks, ) *InAppPurchaseContentResponse`

NewInAppPurchaseContentResponse instantiates a new InAppPurchaseContentResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseContentResponseWithDefaults

`func NewInAppPurchaseContentResponseWithDefaults() *InAppPurchaseContentResponse`

NewInAppPurchaseContentResponseWithDefaults instantiates a new InAppPurchaseContentResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchaseContentResponse) GetData() InAppPurchaseContent`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchaseContentResponse) GetDataOk() (*InAppPurchaseContent, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchaseContentResponse) SetData(v InAppPurchaseContent)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchaseContentResponse) GetIncluded() []InAppPurchaseV2`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchaseContentResponse) GetIncludedOk() (*[]InAppPurchaseV2, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchaseContentResponse) SetIncluded(v []InAppPurchaseV2)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchaseContentResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseContentResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseContentResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseContentResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


