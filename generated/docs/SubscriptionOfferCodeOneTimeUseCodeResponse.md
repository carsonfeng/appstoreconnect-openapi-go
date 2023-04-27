# SubscriptionOfferCodeOneTimeUseCodeResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionOfferCodeOneTimeUseCode**](SubscriptionOfferCodeOneTimeUseCode.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCode**](SubscriptionOfferCode.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionOfferCodeOneTimeUseCodeResponse

`func NewSubscriptionOfferCodeOneTimeUseCodeResponse(data SubscriptionOfferCodeOneTimeUseCode, links DocumentLinks, ) *SubscriptionOfferCodeOneTimeUseCodeResponse`

NewSubscriptionOfferCodeOneTimeUseCodeResponse instantiates a new SubscriptionOfferCodeOneTimeUseCodeResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeOneTimeUseCodeResponseWithDefaults

`func NewSubscriptionOfferCodeOneTimeUseCodeResponseWithDefaults() *SubscriptionOfferCodeOneTimeUseCodeResponse`

NewSubscriptionOfferCodeOneTimeUseCodeResponseWithDefaults instantiates a new SubscriptionOfferCodeOneTimeUseCodeResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) GetData() SubscriptionOfferCodeOneTimeUseCode`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) GetDataOk() (*SubscriptionOfferCodeOneTimeUseCode, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) SetData(v SubscriptionOfferCodeOneTimeUseCode)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) GetIncluded() []SubscriptionOfferCode`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) GetIncludedOk() (*[]SubscriptionOfferCode, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) SetIncluded(v []SubscriptionOfferCode)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCodeOneTimeUseCodeResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


