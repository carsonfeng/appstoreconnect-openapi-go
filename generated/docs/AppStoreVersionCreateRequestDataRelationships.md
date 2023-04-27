# AppStoreVersionCreateRequestDataRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**App** | [**AppAvailabilityCreateRequestDataRelationshipsApp**](AppAvailabilityCreateRequestDataRelationshipsApp.md) |  | 
**AppStoreVersionLocalizations** | Pointer to [**AppStoreVersionCreateRequestDataRelationshipsAppStoreVersionLocalizations**](AppStoreVersionCreateRequestDataRelationshipsAppStoreVersionLocalizations.md) |  | [optional] 
**Build** | Pointer to [**AppStoreVersionCreateRequestDataRelationshipsBuild**](AppStoreVersionCreateRequestDataRelationshipsBuild.md) |  | [optional] 

## Methods

### NewAppStoreVersionCreateRequestDataRelationships

`func NewAppStoreVersionCreateRequestDataRelationships(app AppAvailabilityCreateRequestDataRelationshipsApp, ) *AppStoreVersionCreateRequestDataRelationships`

NewAppStoreVersionCreateRequestDataRelationships instantiates a new AppStoreVersionCreateRequestDataRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionCreateRequestDataRelationshipsWithDefaults

`func NewAppStoreVersionCreateRequestDataRelationshipsWithDefaults() *AppStoreVersionCreateRequestDataRelationships`

NewAppStoreVersionCreateRequestDataRelationshipsWithDefaults instantiates a new AppStoreVersionCreateRequestDataRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetApp

`func (o *AppStoreVersionCreateRequestDataRelationships) GetApp() AppAvailabilityCreateRequestDataRelationshipsApp`

GetApp returns the App field if non-nil, zero value otherwise.

### GetAppOk

`func (o *AppStoreVersionCreateRequestDataRelationships) GetAppOk() (*AppAvailabilityCreateRequestDataRelationshipsApp, bool)`

GetAppOk returns a tuple with the App field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApp

`func (o *AppStoreVersionCreateRequestDataRelationships) SetApp(v AppAvailabilityCreateRequestDataRelationshipsApp)`

SetApp sets App field to given value.


### GetAppStoreVersionLocalizations

`func (o *AppStoreVersionCreateRequestDataRelationships) GetAppStoreVersionLocalizations() AppStoreVersionCreateRequestDataRelationshipsAppStoreVersionLocalizations`

GetAppStoreVersionLocalizations returns the AppStoreVersionLocalizations field if non-nil, zero value otherwise.

### GetAppStoreVersionLocalizationsOk

`func (o *AppStoreVersionCreateRequestDataRelationships) GetAppStoreVersionLocalizationsOk() (*AppStoreVersionCreateRequestDataRelationshipsAppStoreVersionLocalizations, bool)`

GetAppStoreVersionLocalizationsOk returns a tuple with the AppStoreVersionLocalizations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreVersionLocalizations

`func (o *AppStoreVersionCreateRequestDataRelationships) SetAppStoreVersionLocalizations(v AppStoreVersionCreateRequestDataRelationshipsAppStoreVersionLocalizations)`

SetAppStoreVersionLocalizations sets AppStoreVersionLocalizations field to given value.

### HasAppStoreVersionLocalizations

`func (o *AppStoreVersionCreateRequestDataRelationships) HasAppStoreVersionLocalizations() bool`

HasAppStoreVersionLocalizations returns a boolean if a field has been set.

### GetBuild

`func (o *AppStoreVersionCreateRequestDataRelationships) GetBuild() AppStoreVersionCreateRequestDataRelationshipsBuild`

GetBuild returns the Build field if non-nil, zero value otherwise.

### GetBuildOk

`func (o *AppStoreVersionCreateRequestDataRelationships) GetBuildOk() (*AppStoreVersionCreateRequestDataRelationshipsBuild, bool)`

GetBuildOk returns a tuple with the Build field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuild

`func (o *AppStoreVersionCreateRequestDataRelationships) SetBuild(v AppStoreVersionCreateRequestDataRelationshipsBuild)`

SetBuild sets Build field to given value.

### HasBuild

`func (o *AppStoreVersionCreateRequestDataRelationships) HasBuild() bool`

HasBuild returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


