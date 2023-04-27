# AppCustomProductPageLocalizationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppCustomProductPageLocalization**](AppCustomProductPageLocalization.md) |  | 
**Included** | Pointer to [**[]AppCustomProductPageLocalizationsResponseIncludedInner**](AppCustomProductPageLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppCustomProductPageLocalizationResponse

`func NewAppCustomProductPageLocalizationResponse(data AppCustomProductPageLocalization, links DocumentLinks, ) *AppCustomProductPageLocalizationResponse`

NewAppCustomProductPageLocalizationResponse instantiates a new AppCustomProductPageLocalizationResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageLocalizationResponseWithDefaults

`func NewAppCustomProductPageLocalizationResponseWithDefaults() *AppCustomProductPageLocalizationResponse`

NewAppCustomProductPageLocalizationResponseWithDefaults instantiates a new AppCustomProductPageLocalizationResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppCustomProductPageLocalizationResponse) GetData() AppCustomProductPageLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppCustomProductPageLocalizationResponse) GetDataOk() (*AppCustomProductPageLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppCustomProductPageLocalizationResponse) SetData(v AppCustomProductPageLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppCustomProductPageLocalizationResponse) GetIncluded() []AppCustomProductPageLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppCustomProductPageLocalizationResponse) GetIncludedOk() (*[]AppCustomProductPageLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppCustomProductPageLocalizationResponse) SetIncluded(v []AppCustomProductPageLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppCustomProductPageLocalizationResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppCustomProductPageLocalizationResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCustomProductPageLocalizationResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCustomProductPageLocalizationResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


