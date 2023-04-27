# AppStoreVersionExperimentTreatmentLocalizationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppStoreVersionExperimentTreatmentLocalization**](AppStoreVersionExperimentTreatmentLocalization.md) |  | 
**Included** | Pointer to [**[]AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner**](AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppStoreVersionExperimentTreatmentLocalizationResponse

`func NewAppStoreVersionExperimentTreatmentLocalizationResponse(data AppStoreVersionExperimentTreatmentLocalization, links DocumentLinks, ) *AppStoreVersionExperimentTreatmentLocalizationResponse`

NewAppStoreVersionExperimentTreatmentLocalizationResponse instantiates a new AppStoreVersionExperimentTreatmentLocalizationResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentTreatmentLocalizationResponseWithDefaults

`func NewAppStoreVersionExperimentTreatmentLocalizationResponseWithDefaults() *AppStoreVersionExperimentTreatmentLocalizationResponse`

NewAppStoreVersionExperimentTreatmentLocalizationResponseWithDefaults instantiates a new AppStoreVersionExperimentTreatmentLocalizationResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) GetData() AppStoreVersionExperimentTreatmentLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) GetDataOk() (*AppStoreVersionExperimentTreatmentLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) SetData(v AppStoreVersionExperimentTreatmentLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) GetIncluded() []AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) GetIncludedOk() (*[]AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) SetIncluded(v []AppStoreVersionExperimentTreatmentLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperimentTreatmentLocalizationResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


