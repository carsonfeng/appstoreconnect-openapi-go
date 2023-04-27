# AppStoreVersionExperimentResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppStoreVersionExperiment**](AppStoreVersionExperiment.md) |  | 
**Included** | Pointer to [**[]AppStoreVersionExperimentsResponseIncludedInner**](AppStoreVersionExperimentsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppStoreVersionExperimentResponse

`func NewAppStoreVersionExperimentResponse(data AppStoreVersionExperiment, links DocumentLinks, ) *AppStoreVersionExperimentResponse`

NewAppStoreVersionExperimentResponse instantiates a new AppStoreVersionExperimentResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentResponseWithDefaults

`func NewAppStoreVersionExperimentResponseWithDefaults() *AppStoreVersionExperimentResponse`

NewAppStoreVersionExperimentResponseWithDefaults instantiates a new AppStoreVersionExperimentResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppStoreVersionExperimentResponse) GetData() AppStoreVersionExperiment`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppStoreVersionExperimentResponse) GetDataOk() (*AppStoreVersionExperiment, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppStoreVersionExperimentResponse) SetData(v AppStoreVersionExperiment)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppStoreVersionExperimentResponse) GetIncluded() []AppStoreVersionExperimentsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppStoreVersionExperimentResponse) GetIncludedOk() (*[]AppStoreVersionExperimentsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppStoreVersionExperimentResponse) SetIncluded(v []AppStoreVersionExperimentsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppStoreVersionExperimentResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperimentResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperimentResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperimentResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


