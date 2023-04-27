# ReviewSubmissionRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**App** | Pointer to [**AppAvailabilityRelationshipsApp**](AppAvailabilityRelationshipsApp.md) |  | [optional] 
**Items** | Pointer to [**ReviewSubmissionRelationshipsItems**](ReviewSubmissionRelationshipsItems.md) |  | [optional] 
**AppStoreVersionForReview** | Pointer to [**AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersion**](AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersion.md) |  | [optional] 

## Methods

### NewReviewSubmissionRelationships

`func NewReviewSubmissionRelationships() *ReviewSubmissionRelationships`

NewReviewSubmissionRelationships instantiates a new ReviewSubmissionRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionRelationshipsWithDefaults

`func NewReviewSubmissionRelationshipsWithDefaults() *ReviewSubmissionRelationships`

NewReviewSubmissionRelationshipsWithDefaults instantiates a new ReviewSubmissionRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetApp

`func (o *ReviewSubmissionRelationships) GetApp() AppAvailabilityRelationshipsApp`

GetApp returns the App field if non-nil, zero value otherwise.

### GetAppOk

`func (o *ReviewSubmissionRelationships) GetAppOk() (*AppAvailabilityRelationshipsApp, bool)`

GetAppOk returns a tuple with the App field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetApp

`func (o *ReviewSubmissionRelationships) SetApp(v AppAvailabilityRelationshipsApp)`

SetApp sets App field to given value.

### HasApp

`func (o *ReviewSubmissionRelationships) HasApp() bool`

HasApp returns a boolean if a field has been set.

### GetItems

`func (o *ReviewSubmissionRelationships) GetItems() ReviewSubmissionRelationshipsItems`

GetItems returns the Items field if non-nil, zero value otherwise.

### GetItemsOk

`func (o *ReviewSubmissionRelationships) GetItemsOk() (*ReviewSubmissionRelationshipsItems, bool)`

GetItemsOk returns a tuple with the Items field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetItems

`func (o *ReviewSubmissionRelationships) SetItems(v ReviewSubmissionRelationshipsItems)`

SetItems sets Items field to given value.

### HasItems

`func (o *ReviewSubmissionRelationships) HasItems() bool`

HasItems returns a boolean if a field has been set.

### GetAppStoreVersionForReview

`func (o *ReviewSubmissionRelationships) GetAppStoreVersionForReview() AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersion`

GetAppStoreVersionForReview returns the AppStoreVersionForReview field if non-nil, zero value otherwise.

### GetAppStoreVersionForReviewOk

`func (o *ReviewSubmissionRelationships) GetAppStoreVersionForReviewOk() (*AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersion, bool)`

GetAppStoreVersionForReviewOk returns a tuple with the AppStoreVersionForReview field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreVersionForReview

`func (o *ReviewSubmissionRelationships) SetAppStoreVersionForReview(v AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersion)`

SetAppStoreVersionForReview sets AppStoreVersionForReview field to given value.

### HasAppStoreVersionForReview

`func (o *ReviewSubmissionRelationships) HasAppStoreVersionForReview() bool`

HasAppStoreVersionForReview returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


