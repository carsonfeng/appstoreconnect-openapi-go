# AppClipAdvancedExperienceCreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Link** | **string** |  | 
**Action** | Pointer to [**AppClipAction**](AppClipAction.md) |  | [optional] 
**IsPoweredBy** | **bool** |  | 
**Place** | Pointer to [**AppClipAdvancedExperienceAttributesPlace**](AppClipAdvancedExperienceAttributesPlace.md) |  | [optional] 
**BusinessCategory** | Pointer to **string** |  | [optional] 
**DefaultLanguage** | [**AppClipAdvancedExperienceLanguage**](AppClipAdvancedExperienceLanguage.md) |  | 

## Methods

### NewAppClipAdvancedExperienceCreateRequestDataAttributes

`func NewAppClipAdvancedExperienceCreateRequestDataAttributes(link string, isPoweredBy bool, defaultLanguage AppClipAdvancedExperienceLanguage, ) *AppClipAdvancedExperienceCreateRequestDataAttributes`

NewAppClipAdvancedExperienceCreateRequestDataAttributes instantiates a new AppClipAdvancedExperienceCreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAdvancedExperienceCreateRequestDataAttributesWithDefaults

`func NewAppClipAdvancedExperienceCreateRequestDataAttributesWithDefaults() *AppClipAdvancedExperienceCreateRequestDataAttributes`

NewAppClipAdvancedExperienceCreateRequestDataAttributesWithDefaults instantiates a new AppClipAdvancedExperienceCreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLink

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetLink() string`

GetLink returns the Link field if non-nil, zero value otherwise.

### GetLinkOk

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetLinkOk() (*string, bool)`

GetLinkOk returns a tuple with the Link field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLink

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) SetLink(v string)`

SetLink sets Link field to given value.


### GetAction

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetAction() AppClipAction`

GetAction returns the Action field if non-nil, zero value otherwise.

### GetActionOk

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetActionOk() (*AppClipAction, bool)`

GetActionOk returns a tuple with the Action field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAction

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) SetAction(v AppClipAction)`

SetAction sets Action field to given value.

### HasAction

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) HasAction() bool`

HasAction returns a boolean if a field has been set.

### GetIsPoweredBy

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetIsPoweredBy() bool`

GetIsPoweredBy returns the IsPoweredBy field if non-nil, zero value otherwise.

### GetIsPoweredByOk

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetIsPoweredByOk() (*bool, bool)`

GetIsPoweredByOk returns a tuple with the IsPoweredBy field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsPoweredBy

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) SetIsPoweredBy(v bool)`

SetIsPoweredBy sets IsPoweredBy field to given value.


### GetPlace

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetPlace() AppClipAdvancedExperienceAttributesPlace`

GetPlace returns the Place field if non-nil, zero value otherwise.

### GetPlaceOk

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetPlaceOk() (*AppClipAdvancedExperienceAttributesPlace, bool)`

GetPlaceOk returns a tuple with the Place field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPlace

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) SetPlace(v AppClipAdvancedExperienceAttributesPlace)`

SetPlace sets Place field to given value.

### HasPlace

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) HasPlace() bool`

HasPlace returns a boolean if a field has been set.

### GetBusinessCategory

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetBusinessCategory() string`

GetBusinessCategory returns the BusinessCategory field if non-nil, zero value otherwise.

### GetBusinessCategoryOk

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetBusinessCategoryOk() (*string, bool)`

GetBusinessCategoryOk returns a tuple with the BusinessCategory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBusinessCategory

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) SetBusinessCategory(v string)`

SetBusinessCategory sets BusinessCategory field to given value.

### HasBusinessCategory

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) HasBusinessCategory() bool`

HasBusinessCategory returns a boolean if a field has been set.

### GetDefaultLanguage

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetDefaultLanguage() AppClipAdvancedExperienceLanguage`

GetDefaultLanguage returns the DefaultLanguage field if non-nil, zero value otherwise.

### GetDefaultLanguageOk

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) GetDefaultLanguageOk() (*AppClipAdvancedExperienceLanguage, bool)`

GetDefaultLanguageOk returns a tuple with the DefaultLanguage field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDefaultLanguage

`func (o *AppClipAdvancedExperienceCreateRequestDataAttributes) SetDefaultLanguage(v AppClipAdvancedExperienceLanguage)`

SetDefaultLanguage sets DefaultLanguage field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


