# AppCustomProductPageVersionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppCustomProductPageVersion**](AppCustomProductPageVersion.md) |  | 
**Included** | Pointer to [**[]AppCustomProductPageVersionsResponseIncludedInner**](AppCustomProductPageVersionsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppCustomProductPageVersionResponse

`func NewAppCustomProductPageVersionResponse(data AppCustomProductPageVersion, links DocumentLinks, ) *AppCustomProductPageVersionResponse`

NewAppCustomProductPageVersionResponse instantiates a new AppCustomProductPageVersionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPageVersionResponseWithDefaults

`func NewAppCustomProductPageVersionResponseWithDefaults() *AppCustomProductPageVersionResponse`

NewAppCustomProductPageVersionResponseWithDefaults instantiates a new AppCustomProductPageVersionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppCustomProductPageVersionResponse) GetData() AppCustomProductPageVersion`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppCustomProductPageVersionResponse) GetDataOk() (*AppCustomProductPageVersion, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppCustomProductPageVersionResponse) SetData(v AppCustomProductPageVersion)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppCustomProductPageVersionResponse) GetIncluded() []AppCustomProductPageVersionsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppCustomProductPageVersionResponse) GetIncludedOk() (*[]AppCustomProductPageVersionsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppCustomProductPageVersionResponse) SetIncluded(v []AppCustomProductPageVersionsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppCustomProductPageVersionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppCustomProductPageVersionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCustomProductPageVersionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCustomProductPageVersionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


