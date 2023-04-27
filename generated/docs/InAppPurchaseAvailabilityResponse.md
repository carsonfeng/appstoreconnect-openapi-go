# InAppPurchaseAvailabilityResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchaseAvailability**](InAppPurchaseAvailability.md) |  | 
**Included** | Pointer to [**[]Territory**](Territory.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewInAppPurchaseAvailabilityResponse

`func NewInAppPurchaseAvailabilityResponse(data InAppPurchaseAvailability, links DocumentLinks, ) *InAppPurchaseAvailabilityResponse`

NewInAppPurchaseAvailabilityResponse instantiates a new InAppPurchaseAvailabilityResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseAvailabilityResponseWithDefaults

`func NewInAppPurchaseAvailabilityResponseWithDefaults() *InAppPurchaseAvailabilityResponse`

NewInAppPurchaseAvailabilityResponseWithDefaults instantiates a new InAppPurchaseAvailabilityResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchaseAvailabilityResponse) GetData() InAppPurchaseAvailability`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchaseAvailabilityResponse) GetDataOk() (*InAppPurchaseAvailability, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchaseAvailabilityResponse) SetData(v InAppPurchaseAvailability)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchaseAvailabilityResponse) GetIncluded() []Territory`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchaseAvailabilityResponse) GetIncludedOk() (*[]Territory, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchaseAvailabilityResponse) SetIncluded(v []Territory)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchaseAvailabilityResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseAvailabilityResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseAvailabilityResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseAvailabilityResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


