# CiXcodeVersionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiXcodeVersion**](CiXcodeVersion.md) |  | 
**Included** | Pointer to [**[]CiMacOsVersion**](CiMacOsVersion.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiXcodeVersionResponse

`func NewCiXcodeVersionResponse(data CiXcodeVersion, links DocumentLinks, ) *CiXcodeVersionResponse`

NewCiXcodeVersionResponse instantiates a new CiXcodeVersionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiXcodeVersionResponseWithDefaults

`func NewCiXcodeVersionResponseWithDefaults() *CiXcodeVersionResponse`

NewCiXcodeVersionResponseWithDefaults instantiates a new CiXcodeVersionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiXcodeVersionResponse) GetData() CiXcodeVersion`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiXcodeVersionResponse) GetDataOk() (*CiXcodeVersion, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiXcodeVersionResponse) SetData(v CiXcodeVersion)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiXcodeVersionResponse) GetIncluded() []CiMacOsVersion`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiXcodeVersionResponse) GetIncludedOk() (*[]CiMacOsVersion, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiXcodeVersionResponse) SetIncluded(v []CiMacOsVersion)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiXcodeVersionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiXcodeVersionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiXcodeVersionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiXcodeVersionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


