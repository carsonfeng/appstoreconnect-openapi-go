# CiTestResultResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiTestResult**](CiTestResult.md) |  | 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiTestResultResponse

`func NewCiTestResultResponse(data CiTestResult, links DocumentLinks, ) *CiTestResultResponse`

NewCiTestResultResponse instantiates a new CiTestResultResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiTestResultResponseWithDefaults

`func NewCiTestResultResponseWithDefaults() *CiTestResultResponse`

NewCiTestResultResponseWithDefaults instantiates a new CiTestResultResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiTestResultResponse) GetData() CiTestResult`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiTestResultResponse) GetDataOk() (*CiTestResult, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiTestResultResponse) SetData(v CiTestResult)`

SetData sets Data field to given value.


### GetLinks

`func (o *CiTestResultResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiTestResultResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiTestResultResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


