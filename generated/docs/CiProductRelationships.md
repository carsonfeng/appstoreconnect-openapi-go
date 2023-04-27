# CiProductRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**App** | Pointer to [**AppAvailabilityRelationshipsApp**](AppAvailabilityRelationshipsApp.md) |  | [optional] 
**BundleId** | Pointer to [**CiProductRelationshipsBundleId**](CiProductRelationshipsBundleId.md) |  | [optional] 
**PrimaryRepositories** | Pointer to [**CiProductRelationshipsPrimaryRepositories**](CiProductRelationshipsPrimaryRepositories.md) |  | [optional] 

## Methods

### NewCiProductRelationships

`func NewCiProductRelationships() *CiProductRelationships`

NewCiProductRelationships instantiates a new CiProductRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiProductRelationshipsWithDefaults

`func NewCiProductRelationshipsWithDefaults() *CiProductRelationships`

NewCiProductRelationshipsWithDefaults instantiates a new CiProductRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetApp

`func (o *CiProductRelationships) GetApp() AppAvailabilityRelationshipsApp`

GetApp returns the App field if non-nil, zero value otherwise.

### GetAppOk

`func (o *CiProductRelationships) GetAppOk() (*AppAvailabilityRelationshipsApp, bool)`

GetAppOk returns a tuple with the App field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApp

`func (o *CiProductRelationships) SetApp(v AppAvailabilityRelationshipsApp)`

SetApp sets App field to given value.

### HasApp

`func (o *CiProductRelationships) HasApp() bool`

HasApp returns a boolean if a field has been set.

### GetBundleId

`func (o *CiProductRelationships) GetBundleId() CiProductRelationshipsBundleId`

GetBundleId returns the BundleId field if non-nil, zero value otherwise.

### GetBundleIdOk

`func (o *CiProductRelationships) GetBundleIdOk() (*CiProductRelationshipsBundleId, bool)`

GetBundleIdOk returns a tuple with the BundleId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBundleId

`func (o *CiProductRelationships) SetBundleId(v CiProductRelationshipsBundleId)`

SetBundleId sets BundleId field to given value.

### HasBundleId

`func (o *CiProductRelationships) HasBundleId() bool`

HasBundleId returns a boolean if a field has been set.

### GetPrimaryRepositories

`func (o *CiProductRelationships) GetPrimaryRepositories() CiProductRelationshipsPrimaryRepositories`

GetPrimaryRepositories returns the PrimaryRepositories field if non-nil, zero value otherwise.

### GetPrimaryRepositoriesOk

`func (o *CiProductRelationships) GetPrimaryRepositoriesOk() (*CiProductRelationshipsPrimaryRepositories, bool)`

GetPrimaryRepositoriesOk returns a tuple with the PrimaryRepositories field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPrimaryRepositories

`func (o *CiProductRelationships) SetPrimaryRepositories(v CiProductRelationshipsPrimaryRepositories)`

SetPrimaryRepositories sets PrimaryRepositories field to given value.

### HasPrimaryRepositories

`func (o *CiProductRelationships) HasPrimaryRepositories() bool`

HasPrimaryRepositories returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


