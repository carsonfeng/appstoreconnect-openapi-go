# AppStoreVersionExperimentTreatmentResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppStoreVersionExperimentTreatment**](AppStoreVersionExperimentTreatment.md) |  | 
**Included** | Pointer to [**[]AppStoreVersionExperimentTreatmentsResponseIncludedInner**](AppStoreVersionExperimentTreatmentsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppStoreVersionExperimentTreatmentResponse

`func NewAppStoreVersionExperimentTreatmentResponse(data AppStoreVersionExperimentTreatment, links DocumentLinks, ) *AppStoreVersionExperimentTreatmentResponse`

NewAppStoreVersionExperimentTreatmentResponse instantiates a new AppStoreVersionExperimentTreatmentResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentTreatmentResponseWithDefaults

`func NewAppStoreVersionExperimentTreatmentResponseWithDefaults() *AppStoreVersionExperimentTreatmentResponse`

NewAppStoreVersionExperimentTreatmentResponseWithDefaults instantiates a new AppStoreVersionExperimentTreatmentResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionExperimentTreatmentResponse) GetData() AppStoreVersionExperimentTreatment`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionExperimentTreatmentResponse) GetDataOk() (*AppStoreVersionExperimentTreatment, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionExperimentTreatmentResponse) SetData(v AppStoreVersionExperimentTreatment)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionExperimentTreatmentResponse) GetIncluded() []AppStoreVersionExperimentTreatmentsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionExperimentTreatmentResponse) GetIncludedOk() (*[]AppStoreVersionExperimentTreatmentsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionExperimentTreatmentResponse) SetIncluded(v []AppStoreVersionExperimentTreatmentsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionExperimentTreatmentResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperimentTreatmentResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperimentTreatmentResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperimentTreatmentResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


