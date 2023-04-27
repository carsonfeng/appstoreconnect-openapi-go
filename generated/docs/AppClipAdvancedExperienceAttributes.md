# AppClipAdvancedExperienceAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Link** | Pointer to **string** |  | [optional] 
**Version** | Pointer to **int32** |  | [optional] 
**Status** | Pointer to **string** |  | [optional] 
**Action** | Pointer to [**AppClipAction**](AppClipAction.md) |  | [optional] 
**IsPoweredBy** | Pointer to **bool** |  | [optional] 
**Place** | Pointer to [**AppClipAdvancedExperienceAttributesPlace**](AppClipAdvancedExperienceAttributesPlace.md) |  | [optional] 
**PlaceStatus** | Pointer to **string** |  | [optional] 
**BusinessCategory** | Pointer to **string** |  | [optional] 
**DefaultLanguage** | Pointer to [**AppClipAdvancedExperienceLanguage**](AppClipAdvancedExperienceLanguage.md) |  | [optional] 

## Methods

### NewAppClipAdvancedExperienceAttributes

`func NewAppClipAdvancedExperienceAttributes() *AppClipAdvancedExperienceAttributes`

NewAppClipAdvancedExperienceAttributes instantiates a new AppClipAdvancedExperienceAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAdvancedExperienceAttributesWithDefaults

`func NewAppClipAdvancedExperienceAttributesWithDefaults() *AppClipAdvancedExperienceAttributes`

NewAppClipAdvancedExperienceAttributesWithDefaults instantiates a new AppClipAdvancedExperienceAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLink

`func (o *AppClipAdvancedExperienceAttributes) GetLink() string`

GetLink returns the Link field if non-nil, zero value otherwise.

### GetLinkOk

`func (o *AppClipAdvancedExperienceAttributes) GetLinkOk() (*string, bool)`

GetLinkOk returns a tuple with the Link field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLink

`func (o *AppClipAdvancedExperienceAttributes) SetLink(v string)`

SetLink sets Link field to given value.

### HasLink

`func (o *AppClipAdvancedExperienceAttributes) HasLink() bool`

HasLink returns a boolean if a field has been set.

### GetVersion

`func (o *AppClipAdvancedExperienceAttributes) GetVersion() int32`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *AppClipAdvancedExperienceAttributes) GetVersionOk() (*int32, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *AppClipAdvancedExperienceAttributes) SetVersion(v int32)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *AppClipAdvancedExperienceAttributes) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetStatus

`func (o *AppClipAdvancedExperienceAttributes) GetStatus() string`

GetStatus returns the Status field if non-nil, zero value otherwise.

### GetStatusOk

`func (o *AppClipAdvancedExperienceAttributes) GetStatusOk() (*string, bool)`

GetStatusOk returns a tuple with the Status field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStatus

`func (o *AppClipAdvancedExperienceAttributes) SetStatus(v string)`

SetStatus sets Status field to given value.

### HasStatus

`func (o *AppClipAdvancedExperienceAttributes) HasStatus() bool`

HasStatus returns a boolean if a field has been set.

### GetAction

`func (o *AppClipAdvancedExperienceAttributes) GetAction() AppClipAction`

GetAction returns the Action field if non-nil, zero value otherwise.

### GetActionOk

`func (o *AppClipAdvancedExperienceAttributes) GetActionOk() (*AppClipAction, bool)`

GetActionOk returns a tuple with the Action field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAction

`func (o *AppClipAdvancedExperienceAttributes) SetAction(v AppClipAction)`

SetAction sets Action field to given value.

### HasAction

`func (o *AppClipAdvancedExperienceAttributes) HasAction() bool`

HasAction returns a boolean if a field has been set.

### GetIsPoweredBy

`func (o *AppClipAdvancedExperienceAttributes) GetIsPoweredBy() bool`

GetIsPoweredBy returns the IsPoweredBy field if non-nil, zero value otherwise.

### GetIsPoweredByOk

`func (o *AppClipAdvancedExperienceAttributes) GetIsPoweredByOk() (*bool, bool)`

GetIsPoweredByOk returns a tuple with the IsPoweredBy field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsPoweredBy

`func (o *AppClipAdvancedExperienceAttributes) SetIsPoweredBy(v bool)`

SetIsPoweredBy sets IsPoweredBy field to given value.

### HasIsPoweredBy

`func (o *AppClipAdvancedExperienceAttributes) HasIsPoweredBy() bool`

HasIsPoweredBy returns a boolean if a field has been set.

### GetPlace

`func (o *AppClipAdvancedExperienceAttributes) GetPlace() AppClipAdvancedExperienceAttributesPlace`

GetPlace returns the Place field if non-nil, zero value otherwise.

### GetPlaceOk

`func (o *AppClipAdvancedExperienceAttributes) GetPlaceOk() (*AppClipAdvancedExperienceAttributesPlace, bool)`

GetPlaceOk returns a tuple with the Place field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPlace

`func (o *AppClipAdvancedExperienceAttributes) SetPlace(v AppClipAdvancedExperienceAttributesPlace)`

SetPlace sets Place field to given value.

### HasPlace

`func (o *AppClipAdvancedExperienceAttributes) HasPlace() bool`

HasPlace returns a boolean if a field has been set.

### GetPlaceStatus

`func (o *AppClipAdvancedExperienceAttributes) GetPlaceStatus() string`

GetPlaceStatus returns the PlaceStatus field if non-nil, zero value otherwise.

### GetPlaceStatusOk

`func (o *AppClipAdvancedExperienceAttributes) GetPlaceStatusOk() (*string, bool)`

GetPlaceStatusOk returns a tuple with the PlaceStatus field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPlaceStatus

`func (o *AppClipAdvancedExperienceAttributes) SetPlaceStatus(v string)`

SetPlaceStatus sets PlaceStatus field to given value.

### HasPlaceStatus

`func (o *AppClipAdvancedExperienceAttributes) HasPlaceStatus() bool`

HasPlaceStatus returns a boolean if a field has been set.

### GetBusinessCategory

`func (o *AppClipAdvancedExperienceAttributes) GetBusinessCategory() string`

GetBusinessCategory returns the BusinessCategory field if non-nil, zero value otherwise.

### GetBusinessCategoryOk

`func (o *AppClipAdvancedExperienceAttributes) GetBusinessCategoryOk() (*string, bool)`

GetBusinessCategoryOk returns a tuple with the BusinessCategory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBusinessCategory

`func (o *AppClipAdvancedExperienceAttributes) SetBusinessCategory(v string)`

SetBusinessCategory sets BusinessCategory field to given value.

### HasBusinessCategory

`func (o *AppClipAdvancedExperienceAttributes) HasBusinessCategory() bool`

HasBusinessCategory returns a boolean if a field has been set.

### GetDefaultLanguage

`func (o *AppClipAdvancedExperienceAttributes) GetDefaultLanguage() AppClipAdvancedExperienceLanguage`

GetDefaultLanguage returns the DefaultLanguage field if non-nil, zero value otherwise.

### GetDefaultLanguageOk

`func (o *AppClipAdvancedExperienceAttributes) GetDefaultLanguageOk() (*AppClipAdvancedExperienceLanguage, bool)`

GetDefaultLanguageOk returns a tuple with the DefaultLanguage field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDefaultLanguage

`func (o *AppClipAdvancedExperienceAttributes) SetDefaultLanguage(v AppClipAdvancedExperienceLanguage)`

SetDefaultLanguage sets DefaultLanguage field to given value.

### HasDefaultLanguage

`func (o *AppClipAdvancedExperienceAttributes) HasDefaultLanguage() bool`

HasDefaultLanguage returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


