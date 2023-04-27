# InAppPurchaseSubmissionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchaseSubmission**](InAppPurchaseSubmission.md) |  | 
**Included** | Pointer to [**[]InAppPurchaseV2**](InAppPurchaseV2.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewInAppPurchaseSubmissionResponse

`func NewInAppPurchaseSubmissionResponse(data InAppPurchaseSubmission, links DocumentLinks, ) *InAppPurchaseSubmissionResponse`

NewInAppPurchaseSubmissionResponse instantiates a new InAppPurchaseSubmissionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseSubmissionResponseWithDefaults

`func NewInAppPurchaseSubmissionResponseWithDefaults() *InAppPurchaseSubmissionResponse`

NewInAppPurchaseSubmissionResponseWithDefaults instantiates a new InAppPurchaseSubmissionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchaseSubmissionResponse) GetData() InAppPurchaseSubmission`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchaseSubmissionResponse) GetDataOk() (*InAppPurchaseSubmission, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchaseSubmissionResponse) SetData(v InAppPurchaseSubmission)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchaseSubmissionResponse) GetIncluded() []InAppPurchaseV2`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchaseSubmissionResponse) GetIncludedOk() (*[]InAppPurchaseV2, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchaseSubmissionResponse) SetIncluded(v []InAppPurchaseV2)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchaseSubmissionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseSubmissionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseSubmissionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseSubmissionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


