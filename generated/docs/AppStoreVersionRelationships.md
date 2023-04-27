# AppStoreVersionRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**App** | Pointer to [**AppAvailabilityRelationshipsApp**](AppAvailabilityRelationshipsApp.md) |  | [optional] 
**AgeRatingDeclaration** | Pointer to [**AppStoreVersionRelationshipsAgeRatingDeclaration**](AppStoreVersionRelationshipsAgeRatingDeclaration.md) |  | [optional] 
**AppStoreVersionLocalizations** | Pointer to [**AppStoreVersionRelationshipsAppStoreVersionLocalizations**](AppStoreVersionRelationshipsAppStoreVersionLocalizations.md) |  | [optional] 
**Build** | Pointer to [**AppStoreVersionRelationshipsBuild**](AppStoreVersionRelationshipsBuild.md) |  | [optional] 
**AppStoreVersionPhasedRelease** | Pointer to [**AppStoreVersionRelationshipsAppStoreVersionPhasedRelease**](AppStoreVersionRelationshipsAppStoreVersionPhasedRelease.md) |  | [optional] 
**RoutingAppCoverage** | Pointer to [**AppStoreVersionRelationshipsRoutingAppCoverage**](AppStoreVersionRelationshipsRoutingAppCoverage.md) |  | [optional] 
**AppStoreReviewDetail** | Pointer to [**AppStoreReviewAttachmentRelationshipsAppStoreReviewDetail**](AppStoreReviewAttachmentRelationshipsAppStoreReviewDetail.md) |  | [optional] 
**AppStoreVersionSubmission** | Pointer to [**AppStoreVersionRelationshipsAppStoreVersionSubmission**](AppStoreVersionRelationshipsAppStoreVersionSubmission.md) |  | [optional] 
**AppClipDefaultExperience** | Pointer to [**AppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperience**](AppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperience.md) |  | [optional] 
**AppStoreVersionExperiments** | Pointer to [**AppStoreVersionRelationshipsAppStoreVersionExperiments**](AppStoreVersionRelationshipsAppStoreVersionExperiments.md) |  | [optional] 

## Methods

### NewAppStoreVersionRelationships

`func NewAppStoreVersionRelationships() *AppStoreVersionRelationships`

NewAppStoreVersionRelationships instantiates a new AppStoreVersionRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionRelationshipsWithDefaults

`func NewAppStoreVersionRelationshipsWithDefaults() *AppStoreVersionRelationships`

NewAppStoreVersionRelationshipsWithDefaults instantiates a new AppStoreVersionRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetApp

`func (o *AppStoreVersionRelationships) GetApp() AppAvailabilityRelationshipsApp`

GetApp returns the App field if non-nil, zero value otherwise.

### GetAppOk

`func (o *AppStoreVersionRelationships) GetAppOk() (*AppAvailabilityRelationshipsApp, bool)`

GetAppOk returns a tuple with the App field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApp

`func (o *AppStoreVersionRelationships) SetApp(v AppAvailabilityRelationshipsApp)`

SetApp sets App field to given value.

### HasApp

`func (o *AppStoreVersionRelationships) HasApp() bool`

HasApp returns a boolean if a field has been set.

### GetAgeRatingDeclaration

`func (o *AppStoreVersionRelationships) GetAgeRatingDeclaration() AppStoreVersionRelationshipsAgeRatingDeclaration`

GetAgeRatingDeclaration returns the AgeRatingDeclaration field if non-nil, zero value otherwise.

### GetAgeRatingDeclarationOk

`func (o *AppStoreVersionRelationships) GetAgeRatingDeclarationOk() (*AppStoreVersionRelationshipsAgeRatingDeclaration, bool)`

GetAgeRatingDeclarationOk returns a tuple with the AgeRatingDeclaration field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAgeRatingDeclaration

`func (o *AppStoreVersionRelationships) SetAgeRatingDeclaration(v AppStoreVersionRelationshipsAgeRatingDeclaration)`

SetAgeRatingDeclaration sets AgeRatingDeclaration field to given value.

### HasAgeRatingDeclaration

`func (o *AppStoreVersionRelationships) HasAgeRatingDeclaration() bool`

HasAgeRatingDeclaration returns a boolean if a field has been set.

### GetAppStoreVersionLocalizations

`func (o *AppStoreVersionRelationships) GetAppStoreVersionLocalizations() AppStoreVersionRelationshipsAppStoreVersionLocalizations`

GetAppStoreVersionLocalizations returns the AppStoreVersionLocalizations field if non-nil, zero value otherwise.

### GetAppStoreVersionLocalizationsOk

`func (o *AppStoreVersionRelationships) GetAppStoreVersionLocalizationsOk() (*AppStoreVersionRelationshipsAppStoreVersionLocalizations, bool)`

GetAppStoreVersionLocalizationsOk returns a tuple with the AppStoreVersionLocalizations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreVersionLocalizations

`func (o *AppStoreVersionRelationships) SetAppStoreVersionLocalizations(v AppStoreVersionRelationshipsAppStoreVersionLocalizations)`

SetAppStoreVersionLocalizations sets AppStoreVersionLocalizations field to given value.

### HasAppStoreVersionLocalizations

`func (o *AppStoreVersionRelationships) HasAppStoreVersionLocalizations() bool`

HasAppStoreVersionLocalizations returns a boolean if a field has been set.

### GetBuild

`func (o *AppStoreVersionRelationships) GetBuild() AppStoreVersionRelationshipsBuild`

GetBuild returns the Build field if non-nil, zero value otherwise.

### GetBuildOk

`func (o *AppStoreVersionRelationships) GetBuildOk() (*AppStoreVersionRelationshipsBuild, bool)`

GetBuildOk returns a tuple with the Build field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuild

`func (o *AppStoreVersionRelationships) SetBuild(v AppStoreVersionRelationshipsBuild)`

SetBuild sets Build field to given value.

### HasBuild

`func (o *AppStoreVersionRelationships) HasBuild() bool`

HasBuild returns a boolean if a field has been set.

### GetAppStoreVersionPhasedRelease

`func (o *AppStoreVersionRelationships) GetAppStoreVersionPhasedRelease() AppStoreVersionRelationshipsAppStoreVersionPhasedRelease`

GetAppStoreVersionPhasedRelease returns the AppStoreVersionPhasedRelease field if non-nil, zero value otherwise.

### GetAppStoreVersionPhasedReleaseOk

`func (o *AppStoreVersionRelationships) GetAppStoreVersionPhasedReleaseOk() (*AppStoreVersionRelationshipsAppStoreVersionPhasedRelease, bool)`

GetAppStoreVersionPhasedReleaseOk returns a tuple with the AppStoreVersionPhasedRelease field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreVersionPhasedRelease

`func (o *AppStoreVersionRelationships) SetAppStoreVersionPhasedRelease(v AppStoreVersionRelationshipsAppStoreVersionPhasedRelease)`

SetAppStoreVersionPhasedRelease sets AppStoreVersionPhasedRelease field to given value.

### HasAppStoreVersionPhasedRelease

`func (o *AppStoreVersionRelationships) HasAppStoreVersionPhasedRelease() bool`

HasAppStoreVersionPhasedRelease returns a boolean if a field has been set.

### GetRoutingAppCoverage

`func (o *AppStoreVersionRelationships) GetRoutingAppCoverage() AppStoreVersionRelationshipsRoutingAppCoverage`

GetRoutingAppCoverage returns the RoutingAppCoverage field if non-nil, zero value otherwise.

### GetRoutingAppCoverageOk

`func (o *AppStoreVersionRelationships) GetRoutingAppCoverageOk() (*AppStoreVersionRelationshipsRoutingAppCoverage, bool)`

GetRoutingAppCoverageOk returns a tuple with the RoutingAppCoverage field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRoutingAppCoverage

`func (o *AppStoreVersionRelationships) SetRoutingAppCoverage(v AppStoreVersionRelationshipsRoutingAppCoverage)`

SetRoutingAppCoverage sets RoutingAppCoverage field to given value.

### HasRoutingAppCoverage

`func (o *AppStoreVersionRelationships) HasRoutingAppCoverage() bool`

HasRoutingAppCoverage returns a boolean if a field has been set.

### GetAppStoreReviewDetail

`func (o *AppStoreVersionRelationships) GetAppStoreReviewDetail() AppStoreReviewAttachmentRelationshipsAppStoreReviewDetail`

GetAppStoreReviewDetail returns the AppStoreReviewDetail field if non-nil, zero value otherwise.

### GetAppStoreReviewDetailOk

`func (o *AppStoreVersionRelationships) GetAppStoreReviewDetailOk() (*AppStoreReviewAttachmentRelationshipsAppStoreReviewDetail, bool)`

GetAppStoreReviewDetailOk returns a tuple with the AppStoreReviewDetail field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreReviewDetail

`func (o *AppStoreVersionRelationships) SetAppStoreReviewDetail(v AppStoreReviewAttachmentRelationshipsAppStoreReviewDetail)`

SetAppStoreReviewDetail sets AppStoreReviewDetail field to given value.

### HasAppStoreReviewDetail

`func (o *AppStoreVersionRelationships) HasAppStoreReviewDetail() bool`

HasAppStoreReviewDetail returns a boolean if a field has been set.

### GetAppStoreVersionSubmission

`func (o *AppStoreVersionRelationships) GetAppStoreVersionSubmission() AppStoreVersionRelationshipsAppStoreVersionSubmission`

GetAppStoreVersionSubmission returns the AppStoreVersionSubmission field if non-nil, zero value otherwise.

### GetAppStoreVersionSubmissionOk

`func (o *AppStoreVersionRelationships) GetAppStoreVersionSubmissionOk() (*AppStoreVersionRelationshipsAppStoreVersionSubmission, bool)`

GetAppStoreVersionSubmissionOk returns a tuple with the AppStoreVersionSubmission field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreVersionSubmission

`func (o *AppStoreVersionRelationships) SetAppStoreVersionSubmission(v AppStoreVersionRelationshipsAppStoreVersionSubmission)`

SetAppStoreVersionSubmission sets AppStoreVersionSubmission field to given value.

### HasAppStoreVersionSubmission

`func (o *AppStoreVersionRelationships) HasAppStoreVersionSubmission() bool`

HasAppStoreVersionSubmission returns a boolean if a field has been set.

### GetAppClipDefaultExperience

`func (o *AppStoreVersionRelationships) GetAppClipDefaultExperience() AppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperience`

GetAppClipDefaultExperience returns the AppClipDefaultExperience field if non-nil, zero value otherwise.

### GetAppClipDefaultExperienceOk

`func (o *AppStoreVersionRelationships) GetAppClipDefaultExperienceOk() (*AppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperience, bool)`

GetAppClipDefaultExperienceOk returns a tuple with the AppClipDefaultExperience field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppClipDefaultExperience

`func (o *AppStoreVersionRelationships) SetAppClipDefaultExperience(v AppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperience)`

SetAppClipDefaultExperience sets AppClipDefaultExperience field to given value.

### HasAppClipDefaultExperience

`func (o *AppStoreVersionRelationships) HasAppClipDefaultExperience() bool`

HasAppClipDefaultExperience returns a boolean if a field has been set.

### GetAppStoreVersionExperiments

`func (o *AppStoreVersionRelationships) GetAppStoreVersionExperiments() AppStoreVersionRelationshipsAppStoreVersionExperiments`

GetAppStoreVersionExperiments returns the AppStoreVersionExperiments field if non-nil, zero value otherwise.

### GetAppStoreVersionExperimentsOk

`func (o *AppStoreVersionRelationships) GetAppStoreVersionExperimentsOk() (*AppStoreVersionRelationshipsAppStoreVersionExperiments, bool)`

GetAppStoreVersionExperimentsOk returns a tuple with the AppStoreVersionExperiments field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreVersionExperiments

`func (o *AppStoreVersionRelationships) SetAppStoreVersionExperiments(v AppStoreVersionRelationshipsAppStoreVersionExperiments)`

SetAppStoreVersionExperiments sets AppStoreVersionExperiments field to given value.

### HasAppStoreVersionExperiments

`func (o *AppStoreVersionRelationships) HasAppStoreVersionExperiments() bool`

HasAppStoreVersionExperiments returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


