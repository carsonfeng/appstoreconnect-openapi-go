# SubscriptionOfferCodeResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionOfferCode**](SubscriptionOfferCode.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCodesResponseIncludedInner**](SubscriptionOfferCodesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionOfferCodeResponse

`func NewSubscriptionOfferCodeResponse(data SubscriptionOfferCode, links DocumentLinks, ) *SubscriptionOfferCodeResponse`

NewSubscriptionOfferCodeResponse instantiates a new SubscriptionOfferCodeResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeResponseWithDefaults

`func NewSubscriptionOfferCodeResponseWithDefaults() *SubscriptionOfferCodeResponse`

NewSubscriptionOfferCodeResponseWithDefaults instantiates a new SubscriptionOfferCodeResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionOfferCodeResponse) GetData() SubscriptionOfferCode`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionOfferCodeResponse) GetDataOk() (*SubscriptionOfferCode, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionOfferCodeResponse) SetData(v SubscriptionOfferCode)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionOfferCodeResponse) GetIncluded() []SubscriptionOfferCodesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionOfferCodeResponse) GetIncludedOk() (*[]SubscriptionOfferCodesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionOfferCodeResponse) SetIncluded(v []SubscriptionOfferCodesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionOfferCodeResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCodeResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCodeResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCodeResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


