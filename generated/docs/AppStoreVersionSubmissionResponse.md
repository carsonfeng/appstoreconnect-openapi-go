# AppStoreVersionSubmissionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppStoreVersionSubmission**](AppStoreVersionSubmission.md) |  | 
**Included** | Pointer to [**[]AppStoreVersion**](AppStoreVersion.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppStoreVersionSubmissionResponse

`func NewAppStoreVersionSubmissionResponse(data AppStoreVersionSubmission, links DocumentLinks, ) *AppStoreVersionSubmissionResponse`

NewAppStoreVersionSubmissionResponse instantiates a new AppStoreVersionSubmissionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionSubmissionResponseWithDefaults

`func NewAppStoreVersionSubmissionResponseWithDefaults() *AppStoreVersionSubmissionResponse`

NewAppStoreVersionSubmissionResponseWithDefaults instantiates a new AppStoreVersionSubmissionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionSubmissionResponse) GetData() AppStoreVersionSubmission`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionSubmissionResponse) GetDataOk() (*AppStoreVersionSubmission, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionSubmissionResponse) SetData(v AppStoreVersionSubmission)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionSubmissionResponse) GetIncluded() []AppStoreVersion`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionSubmissionResponse) GetIncludedOk() (*[]AppStoreVersion, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionSubmissionResponse) SetIncluded(v []AppStoreVersion)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionSubmissionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionSubmissionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionSubmissionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionSubmissionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


