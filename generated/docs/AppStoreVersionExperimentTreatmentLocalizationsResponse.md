# AppStoreVersionExperimentTreatmentLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppStoreVersionExperimentTreatmentLocalization**](AppStoreVersionExperimentTreatmentLocalization.md) |  | 
**Included** | Pointer to [**[]AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner**](AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppStoreVersionExperimentTreatmentLocalizationsResponse

`func NewAppStoreVersionExperimentTreatmentLocalizationsResponse(data []AppStoreVersionExperimentTreatmentLocalization, links PagedDocumentLinks, ) *AppStoreVersionExperimentTreatmentLocalizationsResponse`

NewAppStoreVersionExperimentTreatmentLocalizationsResponse instantiates a new AppStoreVersionExperimentTreatmentLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentTreatmentLocalizationsResponseWithDefaults

`func NewAppStoreVersionExperimentTreatmentLocalizationsResponseWithDefaults() *AppStoreVersionExperimentTreatmentLocalizationsResponse`

NewAppStoreVersionExperimentTreatmentLocalizationsResponseWithDefaults instantiates a new AppStoreVersionExperimentTreatmentLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetData() []AppStoreVersionExperimentTreatmentLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetDataOk() (*[]AppStoreVersionExperimentTreatmentLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) SetData(v []AppStoreVersionExperimentTreatmentLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetIncluded() []AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetIncludedOk() (*[]AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) SetIncluded(v []AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppStoreVersionExperimentTreatmentLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


