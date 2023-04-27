# CiWorkflowResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CiWorkflow**](CiWorkflow.md) |  | 
**Included** | Pointer to [**[]CiWorkflowsResponseIncludedInner**](CiWorkflowsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCiWorkflowResponse

`func NewCiWorkflowResponse(data CiWorkflow, links DocumentLinks, ) *CiWorkflowResponse`

NewCiWorkflowResponse instantiates a new CiWorkflowResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowResponseWithDefaults

`func NewCiWorkflowResponseWithDefaults() *CiWorkflowResponse`

NewCiWorkflowResponseWithDefaults instantiates a new CiWorkflowResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiWorkflowResponse) GetData() CiWorkflow`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiWorkflowResponse) GetDataOk() (*CiWorkflow, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiWorkflowResponse) SetData(v CiWorkflow)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiWorkflowResponse) GetIncluded() []CiWorkflowsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiWorkflowResponse) GetIncludedOk() (*[]CiWorkflowsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiWorkflowResponse) SetIncluded(v []CiWorkflowsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiWorkflowResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiWorkflowResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiWorkflowResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiWorkflowResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


