# AppStoreVersionExperimentTreatmentsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppStoreVersionExperimentTreatment**](AppStoreVersionExperimentTreatment.md) |  | 
**Included** | Pointer to [**[]AppStoreVersionExperimentTreatmentsResponseIncludedInner**](AppStoreVersionExperimentTreatmentsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppStoreVersionExperimentTreatmentsResponse

`func NewAppStoreVersionExperimentTreatmentsResponse(data []AppStoreVersionExperimentTreatment, links PagedDocumentLinks, ) *AppStoreVersionExperimentTreatmentsResponse`

NewAppStoreVersionExperimentTreatmentsResponse instantiates a new AppStoreVersionExperimentTreatmentsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentTreatmentsResponseWithDefaults

`func NewAppStoreVersionExperimentTreatmentsResponseWithDefaults() *AppStoreVersionExperimentTreatmentsResponse`

NewAppStoreVersionExperimentTreatmentsResponseWithDefaults instantiates a new AppStoreVersionExperimentTreatmentsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetData() []AppStoreVersionExperimentTreatment`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetDataOk() (*[]AppStoreVersionExperimentTreatment, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionExperimentTreatmentsResponse) SetData(v []AppStoreVersionExperimentTreatment)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetIncluded() []AppStoreVersionExperimentTreatmentsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetIncludedOk() (*[]AppStoreVersionExperimentTreatmentsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionExperimentTreatmentsResponse) SetIncluded(v []AppStoreVersionExperimentTreatmentsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionExperimentTreatmentsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperimentTreatmentsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppStoreVersionExperimentTreatmentsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppStoreVersionExperimentTreatmentsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppStoreVersionExperimentTreatmentsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


